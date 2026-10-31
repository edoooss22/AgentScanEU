using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class PerfDataAnalyzer
{
    private const string Nl = "\n";

    private sealed class Counter
    {
        public string Name = "";
        public string Text = "";
        public long Value;
        public bool IsString;
        public char Type;
    }

    private const uint Magic = 0xCAFEC0C0;
    private const uint MagicSwapped = 0xC0C0FECA;

    private static bool IsPerfHeader(ScanContext ctx, ulong at)
    {
        uint v = ctx.Target.ReadU32(at);
        return v == Magic || v == MagicSwapped;
    }

    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        sb.AppendLine(L("VIRTUAL MACHINE PERFORMANCE COUNTERS (hsperfdata)", "CONTADORES DE RENDIMIENTO DE LA MÁQUINA VIRTUAL (hsperfdata)"));
        sb.AppendLine();
        sb.AppendLine(L("The virtual machine maintains this area itself and fills it at startup.", "La máquina virtual mantiene esta área por sí misma y la rellena al arrancar."));
        sb.AppendLine(L("It holds its OWN copy of the command line and class path —", "Contiene su PROPIA copia de la línea de comandos y de la ruta de clases,"));
        sb.AppendLine(L("independent of the process parameter block, which is writable", "independiente del bloque de parámetros del proceso, que cualquier código"));
        sb.AppendLine(L("by any code inside the process.", "dentro del proceso puede modificar."));
        sb.AppendLine();

        ulong at = Find(ctx, out string source);
        sb.AppendLine(L($"  counter area : {(at == 0 ? "NOT FOUND" : $"0x{at:X}")}  {source}", $"  área de contadores : {(at == 0 ? "NO ENCONTRADA" : $"0x{at:X}")}  {source}"));

        if (at == 0)
        {
            sb.AppendLine();
            sb.AppendLine(L("  Area not found. This is not normal: the virtual machine always creates it at", "  Área no encontrada. No es normal: la máquina virtual siempre la crea al"));
            sb.AppendLine(L("  startup unless it was disabled with -XX:-UsePerfData.", "  arrancar, salvo que se desactive con -XX:-UsePerfData."));
            ReportMissing(ctx);
            ctx.Report.Section(L("VM: PERFORMANCE COUNTERS", "VM: CONTADORES DE RENDIMIENTO"), sb.ToString());
            return;
        }

        var counters = Parse(ctx, at, sb);
        if (counters.Count == 0)
        {
            ctx.Report.Section(L("VM: PERFORMANCE COUNTERS", "VM: CONTADORES DE RENDIMIENTO"), sb.ToString());
            return;
        }

        var byName = new Dictionary<string, Counter>(StringComparer.Ordinal);
        foreach (var c in counters) byName[c.Name] = c;

        Render(counters, sb);
        CheckCommandLine(ctx, byName, sb);

        ctx.Report.Section(L("VM: PERFORMANCE COUNTERS", "VM: CONTADORES DE RENDIMIENTO"), sb.ToString());
    }

    private static ulong Find(ScanContext ctx, out string source)
    {
        foreach (var r in ctx.Regions)
        {
            if (!r.IsCommitted || r.IsImage) continue;
            string? f = r.MappedFileDos ?? r.MappedFile;
            if (f is null || !f.Contains("hsperfdata", StringComparison.OrdinalIgnoreCase)) continue;
            if (!IsPerfHeader(ctx, r.Base)) continue;
            source = L("(by mapped file name: ", "(por el nombre del archivo proyectado: ") + f + ")";
            return r.Base;
        }

        foreach (var r in ctx.Regions)
        {
            if (!r.IsCommitted || r.IsImage || r.IsPrivate) continue;
            if (r.Size is < 0x1000 or > 0x100000) continue;
            if (!IsPerfHeader(ctx, r.Base)) continue;
            source = L("(by magic number; mapped file name unavailable)", "(por número mágico; nombre del archivo proyectado no disponible)");
            return r.Base;
        }

        source = "";
        return 0;
    }

    private static void ReportMissing(ScanContext ctx)
    {
        string cmd = ctx.Target.GetCommandLine() ?? "";
        bool off = cmd.Contains("-XX:-UsePerfData", StringComparison.OrdinalIgnoreCase) ||
                   cmd.Contains("PerfDisableSharedMem", StringComparison.OrdinalIgnoreCase);

        ctx.Report.Report(L("VM", "VM"),
                off
                    ? L("VM performance counters are disabled by a startup flag", "Los contadores de rendimiento de la VM están desactivados con una opción de arranque")
                    : L("VM performance counter area not found in memory", "No se encontró en memoria el área de contadores de rendimiento de la VM"),
                off ? Severity.Medium : Severity.High,
                L("The virtual machine always creates the counter area at startup unless it was disabled with -XX:-UsePerfData or -XX:+PerfDisableSharedMem. It holds the VM\'s own copy of the command line — the only source independent of the process parameter block, which is writable from inside. Disabling this area by itself affects neither game performance nor behaviour; its only purpose is to remove the possibility of checking how the process was really started.", "La máquina virtual siempre crea el área de contadores al arrancar, salvo que se desactive con -XX:-UsePerfData o -XX:+PerfDisableSharedMem. Contiene la propia copia de la línea de comandos de la VM: la única fuente independiente del bloque de parámetros del proceso, que puede modificarse desde dentro. Desactivar esta área no afecta por sí solo ni al rendimiento ni al comportamiento del juego; su único propósito es eliminar la posibilidad de comprobar cómo se inició realmente el proceso."))
            .Add(L("command line", "línea de comandos"), JavaMeta.Clean(cmd, 500));
    }

    private static List<Counter> Parse(ScanContext ctx, ulong at, StringBuilder sb)
    {
        var res = new List<Counter>();

        var head = ctx.Target.ReadBytes(at, 32);
        if (head is null) return res;

        byte major = head[5], minor = head[6], accessible = head[7];
        int used = BitConverter.ToInt32(head, 8);
        int overflow = BitConverter.ToInt32(head, 12);
        long modTs = BitConverter.ToInt64(head, 16);
        int entryOffset = BitConverter.ToInt32(head, 24);
        int numEntries = BitConverter.ToInt32(head, 28);

        sb.AppendLine(L($"  format version : {major}.{minor}, accessible: {accessible}", $"  versión del formato : {major}.{minor}, accesible: {accessible}"));
        sb.AppendLine(L($"  used           : {used} bytes, overflow {overflow}", $"  ocupado             : {used} bytes, desbordamiento {overflow}"));
        sb.AppendLine(L($"  entries        : {numEntries}, first at offset {entryOffset}", $"  entradas            : {numEntries}, la primera en el desplazamiento {entryOffset}"));
        sb.AppendLine();

        if (numEntries is <= 0 or > 100_000 || entryOffset is < 32 or > 1 << 20 ||
            used is <= 0 or > 64 * 1024 * 1024)
        {
            sb.AppendLine(L("  header is implausible — parsing not performed.", "  la cabecera no es plausible: no se hizo el análisis."));
            return res;
        }

        var blob = ctx.Target.ReadBytes(at, Math.Min(used + 4096, 8 * 1024 * 1024));
        if (blob is null) return res;

        int pos = entryOffset;
        for (int i = 0; i < numEntries && pos + 20 <= blob.Length; i++)
        {
            int entryLength = BitConverter.ToInt32(blob, pos);
            int nameOffset = BitConverter.ToInt32(blob, pos + 4);
            int vectorLength = BitConverter.ToInt32(blob, pos + 8);
            char dataType = (char)blob[pos + 12];
            int dataOffset = BitConverter.ToInt32(blob, pos + 16);

            if (entryLength is <= 0 or > 1 << 16) break;
            if (pos + entryLength > blob.Length) break;
            if (nameOffset is < 0 || dataOffset < 0 ||
                pos + nameOffset >= blob.Length || pos + dataOffset >= blob.Length)
            { pos += entryLength; continue; }

            var c = new Counter { Name = Cstr(blob, pos + nameOffset, 256), Type = dataType };
            if (c.Name.Length == 0) { pos += entryLength; continue; }

            if (vectorLength > 0)
            {
                c.IsString = true;
                int len = Math.Min(vectorLength, blob.Length - (pos + dataOffset));
                c.Text = len > 0 ? Cstr(blob, pos + dataOffset, len) : "";
            }
            else if (pos + dataOffset + 8 <= blob.Length)
            {
                c.Value = BitConverter.ToInt64(blob, pos + dataOffset);
            }

            res.Add(c);
            pos += entryLength;
        }

        sb.AppendLine(L($"  counters parsed: {res.Count} (strings {res.Count(x => x.IsString)})", $"  contadores analizados: {res.Count} (cadenas {res.Count(x => x.IsString)})"));
        sb.AppendLine(L($"  modification stamp: {modTs}", $"  marca de modificación: {modTs}"));
        sb.AppendLine();
        return res;
    }

    private static string Cstr(byte[] b, int from, int max)
    {
        int n = 0;
        while (n < max && from + n < b.Length && b[from + n] != 0) n++;
        return n == 0 ? "" : Encoding.UTF8.GetString(b, from, n);
    }

    private static void Render(List<Counter> counters, StringBuilder sb)
    {
        var strings = counters.Where(c => c.IsString).OrderBy(c => c.Name, StringComparer.Ordinal).ToList();
        if (strings.Count > 0)
        {
            sb.AppendLine(L("STRING COUNTERS (the VM\'s own data about its startup):", "CONTADORES DE CADENA (datos propios de la VM sobre su arranque):"));
            foreach (var c in strings)
                sb.AppendLine($"  {c.Name,-46} {JavaMeta.Clean(c.Text, 600)}");
            sb.AppendLine();
        }

        sb.AppendLine(L("NUMERIC COUNTERS:", "CONTADORES NUMÉRICOS:"));
        foreach (var c in counters.Where(x => !x.IsString)
                     .OrderBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine($"  {c.Name,-56} {c.Value}");
        sb.AppendLine();
    }

    private static void CheckCommandLine(ScanContext ctx, Dictionary<string, Counter> byName,
        StringBuilder sb)
    {
        string peb = ctx.Target.GetCommandLine() ?? "";

        string vmCommand = Get(byName, "sun.rt.javaCommand");
        string vmArgs = Get(byName, "java.rt.vmArgs");
        string vmFlags = Get(byName, "java.rt.vmFlags");
        if (vmFlags.Length == 0) vmFlags = Get(byName, "sun.rt.vmFlags");
        string classPath = Get(byName, "java.property.java.class.path");
        string libPath = Get(byName, "java.property.java.library.path");

        string argFile = "";
        foreach (string tok in peb.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            string t = tok.Trim('"');
            if (t.StartsWith("@", StringComparison.Ordinal) && t.Length > 1) argFile = t;
        }

        sb.AppendLine(L("STARTUP ARGUMENT RECONCILIATION", "CONCILIACIÓN DE ARGUMENTOS DE ARRANQUE"));
        sb.AppendLine(L($"  process parameter block : {JavaMeta.Clean(peb, 400)}", $"  bloque de parámetros del proceso : {JavaMeta.Clean(peb, 400)}"));
        sb.AppendLine($"  sun.rt.javaCommand       : {JavaMeta.Clean(vmCommand, 400)}");
        sb.AppendLine($"  java.rt.vmArgs           : {JavaMeta.Clean(vmArgs, 900)}");
        if (vmFlags.Length > 0)
            sb.AppendLine($"  java.rt.vmFlags          : {JavaMeta.Clean(vmFlags, 400)}");
        if (classPath.Length > 0)
            sb.AppendLine(L($"  VM class path           : {JavaMeta.Clean(classPath, 900)}", $"  ruta de clases de la VM          : {JavaMeta.Clean(classPath, 900)}"));
        if (libPath.Length > 0)
            sb.AppendLine(L($"  VM library path         : {JavaMeta.Clean(libPath, 400)}", $"  ruta de bibliotecas de la VM     : {JavaMeta.Clean(libPath, 400)}"));
        sb.AppendLine(L($"  argument file           : {(argFile.Length > 0 ? argFile : "not used")}", $"  archivo de argumentos            : {(argFile.Length > 0 ? argFile : "no se usa")}"));
        sb.AppendLine();

        var agents = new List<string>();
        foreach (string src in new[] { vmArgs, vmFlags, vmCommand })
            foreach (string tok in src.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                if (tok.StartsWith("-javaagent", StringComparison.OrdinalIgnoreCase) ||
                    tok.StartsWith("-agentlib", StringComparison.OrdinalIgnoreCase) ||
                    tok.StartsWith("-agentpath", StringComparison.OrdinalIgnoreCase))
                    agents.Add(tok);

        if (agents.Count > 0)
            ctx.Report.Report(L("VM", "VM"),
                    L($"According to the virtual machine\'s own counters, it was started with an agent ({agents.Count})", $"Según los propios contadores de la máquina virtual, se inició con un agente ({agents.Count})"),
                    Severity.Critical,
                    L("The agent flag is visible in the counters the virtual machine filled with its own values at startup. This is independent of the process parameter block, which can be edited from inside, and of the argument file, which can be replaced on disk after startup. A Java agent gets the right to rewrite the bytecode of any game class on the fly.", "La opción del agente es visible en los contadores que la máquina virtual rellenó con sus propios valores al arrancar. Esto es independiente del bloque de parámetros del proceso, que puede editarse desde dentro, y del archivo de argumentos, que puede sustituirse en disco después del arranque. Un agente Java obtiene el derecho de reescribir en caliente el bytecode de cualquier clase del juego."))
                .Add(L("agents", "agentes"), agents.Count.ToString())
                .Add(L("parameter block", "bloque de parámetros"), JavaMeta.Clean(peb, 500))
                .Block(L("Flags", "Opciones"), string.Join(Nl, agents.Select(a => "  " + a)));

        if (argFile.Length > 0)
        {
            sb.AppendLine(L("  Word-by-word comparison not performed: the VM arguments were passed in a file,", "  No se hizo la comparación palabra por palabra: los argumentos de la VM se pasaron en un archivo"));
            sb.AppendLine(L("  and by the way the game is launched they are not in the process parameter block.", "  y, por la forma de lanzar el juego, no están en el bloque de parámetros del proceso."));
            sb.AppendLine();

            ctx.Report.Report(L("VM", "VM"),
                    L("The virtual machine arguments were passed in a file — they cannot be compared with the process parameter block", "Los argumentos de la máquina virtual se pasaron en un archivo: no se pueden comparar con el bloque de parámetros del proceso"),
                    Severity.Info,
                    L("The process command line contains a reference to an argument file, so the arguments themselves are not there and a mismatch with the VM copy would mean nothing. The real virtual machine arguments are shown above from its own counters — read those, not the process command line.", "La línea de comandos del proceso contiene una referencia a un archivo de argumentos, así que los argumentos en sí no están ahí y una discrepancia con la copia de la VM no significaría nada. Los argumentos reales de la máquina virtual se muestran arriba a partir de sus propios contadores: lea esos y no la línea de comandos del proceso."))
                .Add(L("argument file", "archivo de argumentos"), argFile)
                .Add("java.rt.vmArgs", JavaMeta.Clean(vmArgs, 900))
                .Add("sun.rt.javaCommand", JavaMeta.Clean(vmCommand, 500));
            return;
        }

        var missing = new List<string>();
        foreach (string src in new[] { vmCommand, vmArgs })
            foreach (string tok in src.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (tok.Length < 6) continue;
                if (peb.Contains(tok, StringComparison.OrdinalIgnoreCase)) continue;
                if (!missing.Contains(tok)) missing.Add(tok);
            }

        sb.AppendLine(L($"  words from the VM copy missing in the parameter block: {missing.Count}", $"  palabras de la copia de la VM que faltan en el bloque de parámetros: {missing.Count}"));
        sb.AppendLine();

        var f = ctx.Report.Report(L("VM", "VM"),
            missing.Count == 0
                ? L("The VM copy of the startup arguments matches the process parameter block", "La copia de los argumentos de arranque de la VM coincide con el bloque de parámetros del proceso")
                : L($"The VM copy of the arguments differs from the process parameter block ({missing.Count} words)", $"La copia de los argumentos de la VM difiere del bloque de parámetros del proceso ({missing.Count} palabras)"),
            missing.Count == 0 ? Severity.Info : Severity.High,
            L("Everything the scanner knows about how the game was launched is read from the process parameter block. That block lies in process memory, and any code inside can rewrite it: removing «-javaagent:…» from it is a single operation. The virtual machine, however, filled its counters with its own values at startup and does not touch them afterwards. A mismatch means the parameter block was edited — and nobody needs to edit it except whoever hides how the process was launched.", "Todo lo que el escáner sabe sobre cómo se lanzó el juego lo lee del bloque de parámetros del proceso. Ese bloque está en la memoria del proceso y cualquier código interno puede reescribirlo: quitar «-javaagent:…» es una sola operación. En cambio, la máquina virtual rellenó sus contadores con sus propios valores al arrancar y ya no los toca. Una discrepancia significa que el bloque de parámetros se editó, y nadie necesita editarlo salvo quien oculta cómo se lanzó el proceso."));
        f.Add("sun.rt.javaCommand", JavaMeta.Clean(vmCommand, 500))
            .Add("java.rt.vmArgs", JavaMeta.Clean(vmArgs, 900))
            .Add(L("parameter block", "bloque de parámetros"), JavaMeta.Clean(peb, 500));
        if (missing.Count > 0)
            f.Block(L("Words missing in the parameter block", "Palabras que faltan en el bloque de parámetros"),
                string.Join(Nl, missing.Take(40).Select(x => "  " + x)));
    }

    private static string Get(Dictionary<string, Counter> byName, string key) =>
        byName.TryGetValue(key, out var c) ? (c.IsString ? c.Text : c.Value.ToString()) : "";
}
