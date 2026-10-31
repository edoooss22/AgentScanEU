using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class VmEventLogAnalyzer
{
    private static readonly (string Name, string Handle, string What)[] Known =
    {
        ("Dll operation events", "dll",
            L("loading and unloading of native libraries through the VM", "carga y descarga de bibliotecas nativas mediante la VM")),
        ("Classes redefined", "redefine",
            L("on-the-fly class replacement (RedefineClasses / RetransformClasses)", "sustitución de clases en caliente (RedefineClasses / RetransformClasses)")),
        ("Classes unloaded", "unload", L("class unloading", "descarga de clases")),
        ("Classes loaded", "load", L("class loading", "carga de clases")),
        ("Deoptimization events", "deopt", L("deoptimization of compiled code", "desoptimización de código compilado")),
        ("Internal exceptions", "exc", L("internal VM exceptions", "excepciones internas de la VM")),
        ("VM Operations", "vmops", L("VM operations at safepoints", "operaciones de la VM en safepoints")),
        ("Nmethod flushes", "nmethodflushes", L("flushing of compiled methods", "descarte de métodos compilados")),
        ("Memory protections", "memprotect", L("memory protection changes", "cambios de protección de memoria")),
        ("Events", "events", L("general log", "registro general")),
        ("ZGC Phase Switch", "zgcps", L("ZGC phase changes", "cambios de fase de ZGC")),
    };

    private sealed class LogRing
    {
        public string Name = "", Handle = "", What = "";
        public ulong Field;
        public int Length, Index, Count;
        public ulong Records;
        public int Stride, TextOffset;
        public bool HandleOk;
        public List<(double Ts, ulong Thread, string Text)> Entries = new();
    }

    private static int SelfPointerOffset(ScanContext ctx, ulong records)
    {
        var probe = ctx.Target.ReadBytes(records, 256);
        if (probe is null) return -1;
        for (int o = 0; o + 8 <= probe.Length && o <= 128; o += 8)
            if (BitConverter.ToUInt64(probe, o) == records + (ulong)o + 8) return o;
        return -1;
    }

    public static List<RawPattern> Prepare(ScanContext ctx)
    {
        var res = new List<RawPattern>();
        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid) return res;

        var literals = FindLiterals(ctx, jvm,
            Known.Select(k => k.Name).Concat(Known.Select(k => k.Handle)).ToArray());

        foreach (var (name, handle, _) in Known)
        {
            if (!literals.TryGetValue(name, out var nameAddrs)) continue;
            literals.TryGetValue(handle, out var handleAddrs);

            foreach (ulong na in nameAddrs.Take(4))
            {
                var rp = new RawPattern
                {
                    Name = L($"VM log «{name}» @ 0x{na:X}", $"registro de la VM «{name}» @ 0x{na:X}"),
                    Bytes = BitConverter.GetBytes(na),
                    MaxHits = 64,
                };
                ctx.EventLogPatterns.Add((name, handle, na,
                    handleAddrs is { Count: > 0 } ? handleAddrs[0] : 0, rp));
                res.Add(rp);
            }
        }
        return res;
    }

    private static Dictionary<string, List<ulong>> FindLiterals(ScanContext ctx,
        ImageInMemory jvm, string[] wanted)
    {
        var res = new Dictionary<string, List<ulong>>(StringComparer.Ordinal);
        var needles = wanted.Distinct(StringComparer.Ordinal)
            .Select(w => (Text: w, Bytes: Encoding.ASCII.GetBytes(w)))
            .ToList();

        foreach (var sec in jvm.Pe.Sections)
        {
            if (sec.IsExecutable || sec.VirtualSize is 0 or > 64 * 1024 * 1024) continue;
            var buf = new byte[sec.VirtualSize];
            ulong va = jvm.Base + sec.VirtualAddress;
            if (ctx.Target.ReadPartial(va, buf, out _) <= 0) continue;

            foreach (var (text, bytes) in needles)
            {
                for (int i = 1; i + bytes.Length + 1 <= buf.Length; i++)
                {
                    if (buf[i - 1] != 0 || buf[i + bytes.Length] != 0) continue;
                    bool ok = true;
                    for (int k = 0; k < bytes.Length && ok; k++) ok = buf[i + k] == bytes[k];
                    if (!ok) continue;

                    if (!res.TryGetValue(text, out var list)) res[text] = list = new List<ulong>();
                    if (list.Count < 8) list.Add(va + (ulong)i);
                }
            }
        }
        return res;
    }

    public static void Run(ScanContext ctx, SweepResult sweep)
    {
        var sb = new StringBuilder();
        sb.AppendLine(L("HOTSPOT BLACK BOX: VIRTUAL MACHINE EVENT RING LOGS", "CAJA NEGRA DE HOTSPOT: REGISTROS CIRCULARES DE EVENTOS DE LA MÁQUINA VIRTUAL"));
        sb.AppendLine();
        sb.AppendLine(L("The virtual machine keeps eleven ring logs of what it", "La máquina virtual mantiene once registros circulares de lo que"));
        sb.AppendLine(L("did: loading and unloading libraries, loading, unloading and replacing", "ha hecho: carga y descarga de bibliotecas; carga, descarga y sustitución"));
        sb.AppendLine(L("classes, deoptimizations, internal exceptions, VM operations. Each", "de clases; desoptimizaciones; excepciones internas; operaciones de la VM. Cada"));
        sb.AppendLine(L("entry is text with a timestamp from VM start. The mechanism is on by", "entrada es texto con una marca de tiempo desde el inicio de la VM. El mecanismo está activo por"));
        sb.AppendLine(L("default and exists for the crash report, so a cheat usually does not", "defecto y existe para el informe de fallos, así que un cheat normalmente no lo"));
        sb.AppendLine(L("know about it and does not clean its traces there.", "conoce y no borra sus rastros ahí."));
        sb.AppendLine();

        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid)
        {
            sb.AppendLine(L("  jvm.dll not found in the process — the check is not applicable.", "  no se encontró jvm.dll en el proceso: la comprobación no es aplicable."));
            ctx.Report.Section(L("VM: EVENT LOGS (BLACK BOX)", "VM: REGISTROS DE EVENTOS (CAJA NEGRA)"), sb.ToString());
            return;
        }

        CheckDisabled(ctx, sb);

        var rings = Locate(ctx, sweep, sb);
        if (rings.Count == 0)
        {
            sb.AppendLine(L("  No log could be found.", "  No se pudo encontrar ningún registro."));
            sb.AppendLine();
            sb.AppendLine(L("  This is NOT normal for a running virtual machine: logs are created", "  Esto NO es normal en una máquina virtual en ejecución: los registros se crean"));
            sb.AppendLine(L("  at its startup and live until the process ends. Possible causes: logs", "  al arrancar y viven hasta el final del proceso. Posibles causas: los registros"));
            sb.AppendLine(L("  disabled with -XX:-LogEvents (see above), the full memory scan", "  se desactivaron con -XX:-LogEvents (vea arriba), el escaneo completo de memoria"));
            sb.AppendLine(L("  is disabled and the fallback search did not reach the C++ heap, or the log objects", "  está desactivado y la búsqueda alternativa no llegó al heap de C++, o los objetos de registro"));
            sb.AppendLine(L("  were wiped.", "  se borraron."));
            ctx.Report.Report(L("VM", "VM"),
                    L("Virtual machine event ring logs not found in memory", "No se encontraron en memoria los registros circulares de eventos de la máquina virtual"),
                    Severity.Medium,
                    L("Logs are created at VM startup and exist for the whole lifetime of the process. Their absence means either the mechanism was disabled with a flag or the objects were wiped. Both deserve manual review: a normal launcher has no reason to switch off the virtual machine\'s flight recorder.", "Los registros se crean al arrancar la VM y existen durante toda la vida del proceso. Su ausencia significa que el mecanismo se desactivó con una opción o que los objetos se borraron. Ambas cosas merecen una revisión manual: un launcher normal no tiene ningún motivo para apagar el registrador de vuelo de la máquina virtual."))
                .Add(L("logs searched", "registros buscados"), Known.Length.ToString())
                .Add(L("needles registered", "agujas registradas"), ctx.EventLogPatterns.Count.ToString());
            ctx.Report.Section(L("VM: EVENT LOGS (BLACK BOX)", "VM: REGISTROS DE EVENTOS (CAJA NEGRA)"), sb.ToString());
            return;
        }

        foreach (var r in rings) ReadEntries(ctx, r);

        foreach (var r in rings)
        {
            ctx.VmEventRings[r.Handle] = (r.Length, r.Entries.Count);
            foreach (var (ts, th, text) in r.Entries)
                ctx.VmEvents.Add((r.Handle, ts, th, text));
        }

        Render(ctx, rings, sb);

        Verdicts(ctx, rings, sb);

        ctx.Report.Section(L("VM: EVENT LOGS (BLACK BOX)", "VM: REGISTROS DE EVENTOS (CAJA NEGRA)"), sb.ToString());
    }

    private static void CheckDisabled(ScanContext ctx, StringBuilder sb)
    {
        string cmd = ctx.Target.GetCommandLine() ?? "";
        bool off = cmd.Contains("-XX:-LogEvents", StringComparison.OrdinalIgnoreCase);
        bool tiny = cmd.Contains("LogEventsBufferEntries=0", StringComparison.OrdinalIgnoreCase) ||
                    cmd.Contains("LogEventsBufferEntries=1", StringComparison.OrdinalIgnoreCase);

        sb.AppendLine(L($"  logs disabled by a startup flag : {(off ? "YES (-XX:-LogEvents)" : "no")}", $"  registros desactivados con una opción : {(off ? "SÍ (-XX:-LogEvents)" : "no")}"));
        sb.AppendLine(L($"  ring size cut by a flag         : {(tiny ? "YES" : "no")}", $"  tamaño del anillo reducido con una opción : {(tiny ? "SÍ" : "no")}"));
        sb.AppendLine();

        if (!off && !tiny) return;

        ctx.Report.Report(L("VM", "VM"),
                L("The virtual machine flight recorder is disabled by a startup flag", "El registrador de vuelo de la máquina virtual está desactivado con una opción de arranque"),
                Severity.High,
                L("The process command line contains a flag that disables or zeroes the VM event ring logs. It is a diagnostic mechanism enabled by default; it affects neither game performance nor behaviour, and no normal launcher touches it. The only reason to disable it is to leave no records of which libraries and classes were loaded into the process.", "La línea de comandos del proceso contiene una opción que desactiva o anula los registros circulares de eventos de la VM. Es un mecanismo de diagnóstico activo por defecto; no afecta ni al rendimiento ni al comportamiento del juego, y ningún launcher normal lo toca. El único motivo para desactivarlo es no dejar registro de qué bibliotecas y clases se cargaron en el proceso."))
            .Add(L("command line", "línea de comandos"), JavaMeta.Clean(cmd, 600));
    }

    private static List<LogRing> Locate(ScanContext ctx, SweepResult sweep, StringBuilder sb)
    {
        var res = new List<LogRing>();
        var seen = new HashSet<ulong>();

        var candidates = new List<(string Name, string Handle, ulong NameAddr, ulong HandleAddr,
            List<ulong> At)>();

        bool fromSweep = ctx.EventLogPatterns.Count > 0 &&
                         ctx.EventLogPatterns.Any(p => p.Pattern.TotalHits > 0);

        if (fromSweep)
        {
            foreach (var p in ctx.EventLogPatterns)
                candidates.Add((p.Name, p.Handle, p.NameAddr, p.HandleAddr,
                    p.Pattern.Hits.Select(h => h.Addr).Where(a => (a & 7) == 0).ToList()));
            sb.AppendLine(L("  search source : full memory scan", "  fuente de búsqueda : escaneo completo de memoria"));
        }
        else
        {
            var jvm = JvmAnalyzer.FindJvm(ctx);
            if (jvm is null) return res;
            var literals = FindLiterals(ctx, jvm,
                Known.Select(k => k.Name).Concat(Known.Select(k => k.Handle)).ToArray());

            var wanted = new Dictionary<ulong, (string Name, string Handle, ulong HandleAddr)>();
            foreach (var (name, handle, _) in Known)
            {
                if (!literals.TryGetValue(name, out var na) || na.Count == 0) continue;
                literals.TryGetValue(handle, out var ha);
                foreach (ulong a in na.Take(4))
                    wanted[a] = (name, handle, ha is { Count: > 0 } ? ha[0] : 0);
            }
            if (wanted.Count == 0) return res;

            var found = new Dictionary<ulong, List<ulong>>();
            foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateData))
                for (int i = 0; i + 8 <= ch.Length; i += 8)
                {
                    ulong v = BitConverter.ToUInt64(ch.Data, i);
                    if (v == 0 || !wanted.ContainsKey(v)) continue;
                    if (!found.TryGetValue(v, out var list)) found[v] = list = new List<ulong>();
                    ulong at = ch.Base + (ulong)i;
                    if (list.Count > 0 && list[^1] == at) continue;
                    if (list.Count < 256) list.Add(at);
                }

            foreach (var kv in found)
            {
                var w = wanted[kv.Key];
                candidates.Add((w.Name, w.Handle, kv.Key, w.HandleAddr, kv.Value));
            }
            sb.AppendLine(L("  search source : separate pass over private memory (full scan disabled)", "  fuente de búsqueda : pasada aparte por la memoria privada (escaneo completo desactivado)"));
        }

        var cache = new PageCache(ctx.Target, 4096);
        int examined = 0;

        foreach (var (name, handle, nameAddr, handleAddr, at) in candidates)
        {
            string what = Known.FirstOrDefault(k => k.Name == name).What ?? "";
            foreach (ulong field in at)
            {
                examined++;
                if (!seen.Add(field)) continue;

                LogRing? ring = null;
                for (int o = 8; o <= 64 && ring is null; o += 8)
                {
                    int length = (int)cache.U32(field + (ulong)o);
                    int index = (int)cache.U32(field + (ulong)o + 4);
                    int count = (int)cache.U32(field + (ulong)o + 8);
                    ulong records = cache.U64(field + (ulong)o + 16);

                    if (length is < 1 or > 1_000_000) continue;
                    if (index < 0 || index >= length) continue;
                    if (count < 0 || count > length) continue;
                    if (records is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                    if (SelfPointerOffset(ctx, records) < 0) continue;

                    ring = new LogRing
                    {
                        Name = name, Handle = handle, What = what,
                        Field = field, Length = length, Index = index, Count = count,
                        Records = records,
                        HandleOk = MatchesAscii(cache, cache.U64(field + 8), handle),
                    };
                }
                if (ring is null) continue;

                res.Add(ring);
                break;
            }
        }

        sb.AppendLine(L($"  places checked: {examined}", $"  lugares comprobados: {examined}"));
        sb.AppendLine(L($"  logs found    : {res.Count} of {Known.Length}", $"  registros encontrados: {res.Count} de {Known.Length}"));
        sb.AppendLine();

        sb.AppendLine(L($"{"LOG",-24} {"LITERAL",-12} {"PLACES",-6} {"FOUND",-9} NOTE", $"{"REGISTRO",-24} {"LITERAL",-12} {"LUGARES",-6} {"HALLADO",-9} NOTA"));
        sb.AppendLine(new string('-', 100));
        foreach (var (name, handle, _) in Known)
        {
            var cand = candidates.Where(c => c.Name == name).ToList();
            bool literal = cand.Count > 0;
            int places = cand.Sum(c => c.At.Count);
            bool ok = res.Any(r => r.Name == name);
            string note = ok ? "" :
                !literal ? L("name string not found in jvm.dll", "no se encontró la cadena del nombre en jvm.dll") :
                places == 0 ? L("no pointer to the string in memory — the log was not created", "no hay puntero a la cadena en memoria: el registro no se creó") :
                L("place found, but the field check failed", "se encontró el lugar, pero la comprobación de campos falló");
            sb.AppendLine(L($"{name,-24} {(literal ? "yes" : "NO"),-12} {places,-6} {(ok ? "yes" : "no"),-9} {note}", $"{name,-24} {(literal ? "sí" : "NO"),-12} {places,-6} {(ok ? "sí" : "no"),-9} {note}"));
        }
        sb.AppendLine();
        return res;
    }

    private static bool MatchesAscii(PageCache c, ulong addr, string s)
    {
        if (addr is < 0x10000 or > 0x7FFFFFFFFFFF) return false;
        var buf = c.Read(addr, s.Length + 1);
        if (buf is null || buf[s.Length] != 0) return false;
        for (int i = 0; i < s.Length; i++) if (buf[i] != (byte)s[i]) return false;
        return true;
    }

    private static void ReadEntries(ScanContext ctx, LogRing r)
    {
        const int Probe = 8192;
        var probe = ctx.Target.ReadBytes(r.Records, Probe);
        if (probe is null) return;

        int self = SelfPointerOffset(ctx, r.Records);
        if (self < 0) return;

        int stride = -1;
        for (int o = self + 8; o + 8 <= Probe; o += 8)
            if (BitConverter.ToUInt64(probe, o) == r.Records + (ulong)o + 8)
            { stride = o - self; break; }
        if (stride is < 32 or > 8192) return;

        r.Stride = stride;
        r.TextOffset = self + 8;
        int textMax = stride - r.TextOffset + self - self;
        if (textMax is < 16 or > 8192) textMax = stride - r.TextOffset;

        long total = (long)stride * r.Length;
        if (total is <= 0 or > 64 * 1024 * 1024) return;
        var all = ctx.Target.ReadBytes(r.Records, (int)total);
        if (all is null) return;

        var order = new List<int>(r.Count);
        if (r.Count < r.Length) for (int i = 0; i < r.Count; i++) order.Add(i);
        else
        {
            for (int i = r.Index; i < r.Length; i++) order.Add(i);
            for (int i = 0; i < r.Index; i++) order.Add(i);
        }

        foreach (int slot in order)
        {
            int b = slot * stride;
            if (b + stride > all.Length) break;
            double ts = BitConverter.ToDouble(all, b + self - 16);
            ulong th = BitConverter.ToUInt64(all, b + self - 8);

            int t = b + r.TextOffset;
            int end = t;
            int limit = Math.Min(all.Length, b + stride);
            while (end < limit && all[end] != 0) end++;
            string text = Encoding.UTF8.GetString(all, t, end - t);

            if (text.Length == 0 && ts == 0) continue;
            r.Entries.Add((ts, th, Clean(text)));
        }
    }

    private static string Clean(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char ch in s) sb.Append(ch is '\n' or '\r' ? ' ' : ch < 0x20 ? '.' : ch);
        return sb.ToString().TrimEnd();
    }

    private static void Render(ScanContext ctx, List<LogRing> rings, StringBuilder sb)
    {
        DateTime start = ctx.Target.StartTimeUtc;

        sb.AppendLine(L($"{"LOG",-24} {"RING",-8} {"ENTRIES",-9} {"STEP",-7} MEANING", $"{"REGISTRO",-24} {"ANILLO",-8} {"ENTRADAS",-9} {"PASO",-7} SIGNIFICADO"));
        sb.AppendLine(new string('-', 118));
        foreach (var r in rings.OrderBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine($"{r.Name,-24} {r.Length,-8} {r.Entries.Count,-9} {r.Stride,-7} {r.What}");
        sb.AppendLine();

        foreach (var r in rings)
        {
            sb.AppendLine($"=== {r.Name} ({r.Handle}) — {r.What}");
            sb.AppendLine(L($"    object: name field 0x{r.Field:X}, record array 0x{r.Records:X}, ring {r.Length}, position {r.Index}, entries {r.Count}", $"    objeto: campo de nombre 0x{r.Field:X}, array de registros 0x{r.Records:X}, anillo {r.Length}, posición {r.Index}, entradas {r.Count}"));
            if (r.Entries.Count == 0) sb.AppendLine(L("    (empty)", "    (vacío)"));
            foreach (var (ts, th, text) in r.Entries)
            {
                string wall = start == default
                    ? ""
                    : start.AddSeconds(ts).ToString("HH:mm:ss.fff") + " UTC  ";
                sb.AppendLine(L($"    +{ts,10:F3} s  {wall}thread 0x{th:X}  {text}", $"    +{ts,10:F3} s  {wall}hilo 0x{th:X}  {text}"));
            }
            sb.AppendLine();
        }
    }

    private static void Verdicts(ScanContext ctx, List<LogRing> rings, StringBuilder sb)
    {
        var byName = rings.ToDictionary(r => r.Name, r => r, StringComparer.Ordinal);

        WipedCheck(ctx, rings, sb);
        DllVerdict(ctx, byName, sb);
        RedefineVerdict(ctx, byName, sb);
        ClassVerdict(ctx, byName, sb);

        ctx.Report.Report(L("VM", "VM"),
                L($"The virtual machine flight recorder was read: {rings.Count} logs, {rings.Sum(r => r.Entries.Count)} entries", $"Se leyó el registrador de vuelo de la máquina virtual: {rings.Count} registros, {rings.Sum(r => r.Entries.Count)} entradas"),
                Severity.Info,
                L("HotSpot ring logs: what the virtual machine did and when. The entries were made by the VM itself, not reconstructed from fragments, and each has a timestamp from VM start. The section is output in full: it is a ready-made timeline of the process, which a human can match against what the other checks found.", "Registros circulares de HotSpot: qué hizo la máquina virtual y cuándo. Las entradas las escribió la propia VM, no se reconstruyeron a partir de fragmentos, y cada una tiene una marca de tiempo desde el inicio de la VM. La sección se muestra completa: es una cronología lista del proceso que una persona puede contrastar con lo que encontraron las demás comprobaciones."))
            .Add(L("logs", "registros"), rings.Count.ToString())
            .Add(L("entries", "entradas"), rings.Sum(r => r.Entries.Count).ToString())
            .Block(L("Log summary", "Resumen de registros"), string.Join("\n", rings
                .Select(r => L($"  {r.Name,-24} entries {r.Entries.Count,3} of {r.Length,-4} — {r.What}", $"  {r.Name,-24} entradas {r.Entries.Count,3} de {r.Length,-4} — {r.What}"))));
    }

    private static void WipedCheck(ScanContext ctx, List<LogRing> rings, StringBuilder sb)
    {
        var loaded = rings.FirstOrDefault(r => r.Name == "Classes loaded");
        var vmops = rings.FirstOrDefault(r => r.Name == "VM Operations");
        double uptime = ctx.Target.StartTimeUtc == default
            ? 0 : (DateTime.UtcNow - ctx.Target.StartTimeUtc).TotalSeconds;

        var empty = new List<LogRing>();
        if (loaded is { Count: 0 }) empty.Add(loaded);
        if (vmops is { Count: 0 }) empty.Add(vmops);
        if (empty.Count == 0 || uptime < 60) return;

        sb.AppendLine(L("EMPTY LOGS:", "REGISTROS VACÍOS:"));
        foreach (var r in empty) sb.AppendLine($"    {r.Name}");
        sb.AppendLine();

        ctx.Report.Report(L("VM", "VM"),
                L($"VM event logs exist but are empty ({string.Join(", ", empty.Select(r => r.Name))})", $"Los registros de eventos de la VM existen pero están vacíos ({string.Join(", ", empty.Select(r => r.Name))})"),
                Severity.Critical,
                L("Class loading and virtual machine operations go on continuously while the game runs, so in a process running for more than a minute these rings are always filled. An empty ring with a live log object means the content was wiped deliberately: the VM itself does not reset the entry counter.", "La carga de clases y las operaciones de la máquina virtual ocurren continuamente mientras el juego se ejecuta, así que en un proceso que lleva más de un minuto en marcha estos anillos siempre están llenos. Un anillo vacío con un objeto de registro vivo significa que el contenido se borró a propósito: la propia VM no reinicia el contador de entradas."))
            .Add(L("process running, s", "proceso en ejecución, s"), uptime.ToString("F0"))
            .Add(L("empty logs", "registros vacíos"), empty.Count.ToString());
    }

    private static void DllVerdict(ScanContext ctx, Dictionary<string, LogRing> byName,
        StringBuilder sb)
    {
        if (!byName.TryGetValue("Dll operation events", out var r) || r.Entries.Count == 0) return;

        var loadedNow = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var im in ctx.Images)
        {
            loadedNow.Add(im.Name);
            if (im.Path is { Length: > 0 }) loadedNow.Add(Path.GetFileName(im.Path));
        }

        var unloads = new List<(double Ts, string Path)>();
        var gone = new List<(double Ts, string Path)>();
        var late = new List<(double Ts, string Path)>();

        double firstTs = r.Entries.Min(e => e.Ts);

        foreach (var (ts, _, text) in r.Entries)
        {
            string? path = ExtractPath(text);
            if (path is null) continue;
            string file = Path.GetFileName(path);
            bool isUnload = text.Contains("nloaded", StringComparison.Ordinal);

            if (isUnload) unloads.Add((ts, path));
            else if (!loadedNow.Contains(file)) gone.Add((ts, path));

            if (!isUnload && ts - firstTs > 60) late.Add((ts, path));
        }

        sb.AppendLine(L("LIBRARY OPERATIONS LOG ANALYSIS:", "ANÁLISIS DEL REGISTRO DE OPERACIONES CON BIBLIOTECAS:"));
        sb.AppendLine(L($"    unload entries                             : {unloads.Count}", $"    entradas de descarga                         : {unloads.Count}"));
        sb.AppendLine(L($"    loaded, but NOT in the process now         : {gone.Count}", $"    cargadas, pero que AHORA NO están en el proceso : {gone.Count}"));
        sb.AppendLine(L($"    loaded more than a minute after the first  : {late.Count}", $"    cargadas más de un minuto después de la primera : {late.Count}"));
        foreach (var (ts, p) in unloads) sb.AppendLine(L($"      unload     +{ts,10:F3} s  {p}", $"      descarga   +{ts,10:F3} s  {p}"));
        foreach (var (ts, p) in gone) sb.AppendLine(L($"      gone now   +{ts,10:F3} s  {p}", $"      ya no está +{ts,10:F3} s  {p}"));
        foreach (var (ts, p) in late) sb.AppendLine(L($"      late       +{ts,10:F3} s  {p}", $"      tardía     +{ts,10:F3} s  {p}"));
        sb.AppendLine();

        if (unloads.Count > 0)
            ctx.Report.Report(L("VM", "VM"),
                    L($"The virtual machine recorded the unloading of {unloads.Count} native libraries", $"La máquina virtual registró la descarga de {unloads.Count} bibliotecas nativas"),
                    Severity.Critical,
                    L("The VM itself writes the «Unloaded dll» entry when a native library is unloaded from the process. The Minecraft client never unloads its libraries: they are loaded at startup and live until the game exits. An unload means a foreign library was loaded into the process and removed — the very «self-destruct» the scanner is run for. The file path is kept in the entry in full, even if the file itself is no longer on disk.", "La propia VM escribe la entrada «Unloaded dll» cuando una biblioteca nativa se descarga del proceso. El cliente de Minecraft nunca descarga sus bibliotecas: se cargan al arrancar y viven hasta que el juego se cierra. Una descarga significa que se cargó una biblioteca ajena en el proceso y se retiró: justo la «autodestrucción» por la que se ejecuta el escáner. La ruta del archivo se conserva completa en la entrada, aunque el archivo ya no esté en el disco."))
                .Add(L("entries", "entradas"), unloads.Count.ToString())
                .Block(L("Unloaded libraries", "Bibliotecas descargadas"), string.Join("\n", unloads
                    .Select(u => L($"  +{u.Ts:F3} s  {u.Path}", $"  +{u.Ts:F3} s  {u.Path}"))));

        if (gone.Count > 0)
            ctx.Report.Report(L("VM", "VM"),
                    L($"{gone.Count} libraries are listed as loaded in the VM log, but they are not in the process now", $"{gone.Count} bibliotecas figuran como cargadas en el registro de la VM, pero ahora no están en el proceso"),
                    Severity.Critical,
                    L("The virtual machine recorded the library being loaded, but it is no longer in the loader lists. This is evidence, independent of Windows, that the module was in the process and disappeared: the VM keeps the log while the image loader keeps the module lists, and both would have to be forged.", "La máquina virtual registró la carga de la biblioteca, pero ya no está en las listas del cargador. Es una prueba, independiente de Windows, de que el módulo estuvo en el proceso y desapareció: el registro lo lleva la VM y las listas de módulos el cargador de imágenes, así que habría que falsificar ambos."))
                .Add(L("libraries", "bibliotecas"), gone.Count.ToString())
                .Block(L("Libraries", "Bibliotecas"), string.Join("\n", gone
                    .Select(u => L($"  +{u.Ts:F3} s  {u.Path}", $"  +{u.Ts:F3} s  {u.Path}"))));

        if (late.Count > 0)
            ctx.Report.Report(L("VM", "VM"),
                    L($"{late.Count} native libraries were loaded much later than the others", $"{late.Count} bibliotecas nativas se cargaron mucho después que las demás"),
                    Severity.High,
                    L("The game loads its native libraries in one batch at startup and does not come back to them. A load more than a minute after the start of this batch happened during play. That is not evidence by itself — voice chat libraries and parts of mods load on demand this way — but the path and time are exact and worth matching against the other findings.", "El juego carga sus bibliotecas nativas en una sola tanda al arrancar y no vuelve a ellas. Una carga que ocurre más de un minuto después del inicio de esa tanda se produjo durante la partida. Eso no es una prueba por sí solo (las bibliotecas de chat de voz y partes de algunos mods se cargan así bajo demanda), pero la ruta y la hora son exactas y conviene contrastarlas con los demás hallazgos."))
                .Add(L("libraries", "bibliotecas"), late.Count.ToString())
                .Block(L("Libraries", "Bibliotecas"), string.Join("\n", late
                    .Select(u => L($"  +{u.Ts:F3} s  {u.Path}", $"  +{u.Ts:F3} s  {u.Path}"))));
    }

    private static string? ExtractPath(string text)
    {
        int q1 = text.IndexOf('"');
        if (q1 >= 0)
        {
            int q2 = text.IndexOf('"', q1 + 1);
            if (q2 > q1 + 1) return text[(q1 + 1)..q2];
        }

        int dot = text.LastIndexOf(".dll", StringComparison.OrdinalIgnoreCase);
        if (dot < 0) dot = text.LastIndexOf(".so", StringComparison.OrdinalIgnoreCase);
        if (dot < 0) return null;

        int end = dot + (text[dot..].StartsWith(".dll", StringComparison.OrdinalIgnoreCase) ? 4 : 3);
        int start = end;
        while (start > 0 && text[start - 1] is not (' ' or '\t' or '"' or '[' or '(')) start--;
        string p = text[start..end].Trim();
        return p.Length >= 5 ? p : null;
    }

    private static void RedefineVerdict(ScanContext ctx, Dictionary<string, LogRing> byName,
        StringBuilder sb)
    {
        if (!byName.TryGetValue("Classes redefined", out var r) || r.Entries.Count == 0) return;

        sb.AppendLine(L($"CLASS REDEFINITION LOG ANALYSIS: entries {r.Entries.Count}", $"ANÁLISIS DEL REGISTRO DE REDEFINICIÓN DE CLASES: entradas {r.Entries.Count}"));
        foreach (var (ts, _, text) in r.Entries) sb.AppendLine(L($"    +{ts,10:F3} s  {text}", $"    +{ts,10:F3} s  {text}"));
        sb.AppendLine();

        ctx.Report.Report(L("VM", "VM"),
                L($"The virtual machine recorded {r.Entries.Count} on-the-fly class replacement events", $"La máquina virtual registró {r.Entries.Count} eventos de sustitución de clases en caliente"),
                Severity.Critical,
                L("Entries in this log are made only by RedefineClasses / RetransformClasses — i.e. by a JVMTI agent replacing the code of already loaded classes. Unlike the IS_OLD flags of Method objects, which only say «a replacement happened», this log records the NAMES of the replaced classes and the TIME of each replacement. The only normal reason for such entries is a debugger or profiler attached to the game.", "Las entradas de este registro solo las crea RedefineClasses / RetransformClasses, es decir, un agente JVMTI que sustituye el código de clases ya cargadas. A diferencia de las banderas IS_OLD de los objetos Method, que solo dicen «hubo una sustitución», aquí quedan los NOMBRES de las clases sustituidas y la HORA de cada sustitución. La única razón normal para estas entradas es un depurador o un perfilador conectado al juego."))
            .Add(L("events", "eventos"), r.Entries.Count.ToString())
            .Block(L("Entries", "Entradas"), string.Join("\n", r.Entries
                .Select(e => L($"  +{e.Ts:F3} s  {e.Text}", $"  +{e.Ts:F3} s  {e.Text}"))));
    }

    private static void ClassVerdict(ScanContext ctx, Dictionary<string, LogRing> byName,
        StringBuilder sb)
    {
        if (ctx.Jars is null) return;

        foreach (string logName in new[] { "Classes loaded", "Classes unloaded" })
        {
            if (!byName.TryGetValue(logName, out var r) || r.Entries.Count == 0) continue;

            var foreign = new List<(double Ts, string Cls)>();
            foreach (var (ts, _, text) in r.Entries)
            {
                string? cls = ExtractClassName(text);
                if (cls is null) continue;
                if (JarIndex.IsRuntimeClass(cls)) continue;
                if (JarIndex.GeneratedKind(cls) is not null) continue;
                if (ctx.Jars.Contains(cls)) continue;
                foreign.Add((ts, cls));
            }

            sb.AppendLine(L($"LOG «{logName}» ANALYSIS: entries {r.Entries.Count}, classes outside archives {foreign.Count}", $"ANÁLISIS DEL REGISTRO «{logName}»: entradas {r.Entries.Count}, clases fuera de los archivos {foreign.Count}"));
            foreach (var (ts, cls) in foreign) sb.AppendLine(L($"    +{ts,10:F3} s  {cls}", $"    +{ts,10:F3} s  {cls}"));
            sb.AppendLine();

            if (foreign.Count == 0) continue;

            bool unload = logName == "Classes unloaded";
            ctx.Report.Report(L("VM", "VM"),
                    L($"The «{logName}» log has {foreign.Count} classes that are not in any archive available to the game", $"El registro «{logName}» tiene {foreign.Count} clases que no están en ningún archivo disponible para el juego"),
                    unload ? Severity.Critical : Severity.High,
                    (unload
                        ? L("The virtual machine recorded the UNLOADING of these classes. Unloading happens when the loader that defined them dies — i.e. the code was loaded dynamically and cleaned up after itself. ", "La máquina virtual registró la DESCARGA de estas clases. La descarga ocurre cuando muere el cargador que las definió, es decir, el código se cargó dinámicamente y se limpió a sí mismo. ")
                        : L("The virtual machine recorded the loading of these classes. ", "La máquina virtual registró la carga de estas clases. ")) +
                    L("At the same time, the bytecode of these classes is in no jar archive on the game class path, they do not belong to the Java runtime and are not generated by the VM itself. The entry was made by the virtual machine itself and contains the time — direct evidence, not a reconstruction from fragments.", "Al mismo tiempo, el bytecode de estas clases no está en ningún archivo jar de la ruta de clases del juego, no pertenecen al entorno de ejecución de Java ni las genera la propia VM. La entrada la escribió la propia máquina virtual y contiene la hora: es una prueba directa, no una reconstrucción a partir de fragmentos."))
                .Add(L("classes", "clases"), foreign.Count.ToString())
                .Add(L("archives in the index", "archivos en el índice"), ctx.Jars.Jars.Count.ToString())
                .Block(L("Classes", "Clases"), string.Join("\n", foreign
                    .Select(f => L($"  +{f.Ts:F3} s  {f.Cls}", $"  +{f.Ts:F3} s  {f.Cls}"))));
        }
    }

    private static string? ExtractClassName(string text)
    {
        int q1 = text.IndexOf('\'');
        if (q1 >= 0)
        {
            int q2 = text.IndexOf('\'', q1 + 1);
            if (q2 > q1 + 1) return text[(q1 + 1)..q2].Replace('.', '/');
        }

        const string p = "class ";
        int i = text.IndexOf(p, StringComparison.Ordinal);
        if (i < 0) return null;
        string rest = text[(i + p.Length)..].Trim();
        int sp = rest.IndexOf(' ');
        if (sp > 0) rest = rest[..sp];
        if (rest.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return null;
        rest = rest.Replace('.', '/');
        return rest.Length is >= 3 and <= 512 ? rest : null;
    }
}
