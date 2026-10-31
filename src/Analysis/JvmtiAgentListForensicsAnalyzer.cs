using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JvmtiAgentListForensicsAnalyzer
{
    public static void Run(ScanContext ctx)
    {
        var jvm = JvmAnalyzer.FindJvm(ctx);
        var sb = new StringBuilder();

        sb.AppendLine(L("Agent lists and attach mechanism structures are read directly from", "Las listas de agentes y las estructuras del mecanismo attach se leen directamente de"));
        sb.AppendLine(L("virtual machine memory. There are no symbols for them, so identification", "la memoria de la máquina virtual. No hay símbolos para ellas, así que la identificación"));
        sb.AppendLine(L("is structural: a record is accepted only if ALL its fields agree.", "es estructural: un registro solo se acepta si TODOS sus campos coinciden."));
        sb.AppendLine();

        if (jvm is null || !jvm.Pe.Valid)
        {
            sb.AppendLine(L("jvm.dll not found or its headers not parsed — the check is impossible.", "no se encontró jvm.dll o no se analizaron sus cabeceras: la comprobación es imposible."));
            ctx.Report.Section(L("HOTSPOT AGENT LISTS AND THE ATTACH MECHANISM", "LISTAS DE AGENTES DE HOTSPOT Y MECANISMO ATTACH"), sb.ToString());
            return;
        }

        var agents = FindAgentList(ctx, jvm, sb);
        ReportAgents(ctx, agents, sb);
        FindAttachOperations(ctx, jvm, sb);
        FindAgentStrings(ctx, sb);

        ctx.Report.Section(L("HOTSPOT AGENT LISTS AND THE ATTACH MECHANISM", "LISTAS DE AGENTES DE HOTSPOT Y MECANISMO ATTACH"), sb.ToString());
    }

    private sealed class ListHit
    {
        public ulong HeadVar;
        public List<AgentRecord> Chain = new();
        public string How = "";
    }

    private static List<AgentRecord> FindAgentList(ScanContext ctx, ImageInMemory jvm,
        StringBuilder sb)
    {
        var result = new List<AgentRecord>();
        var seen = new HashSet<ulong>();
        var hits = new List<ListHit>();

        sb.AppendLine(L("SEARCH FOR THE AGENT LIST HEAD IN jvm.dll DATA", "BÚSQUEDA DE LA CABEZA DE LA LISTA DE AGENTES EN LOS DATOS DE jvm.dll"));

        foreach (var sec in jvm.Pe.Sections)
        {
            if (sec.IsExecutable || sec.VirtualSize is 0 or > 32 * 1024 * 1024) continue;
            if (sec.Name is not (".data" or ".rdata" or ".bss")) continue;

            var buf = new byte[sec.VirtualSize];
            ulong va = jvm.Base + sec.VirtualAddress;
            if (ctx.Target.ReadPartial(va, buf, out _) <= 0) continue;

            for (int i = 0; i + 8 <= buf.Length; i += 8)
            {
                ulong p = BitConverter.ToUInt64(buf, i);
                if (p is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                if (p >= jvm.Base && p < jvm.End) continue;
                var reg = ctx.RegionAt(p);
                if (reg is null || !reg.IsCommitted || !reg.IsPrivate || reg.IsExecutable) continue;

                var rec = JvmtiAgentProbe.TryRead(ctx, p);
                if (rec is null) continue;

                var hit = new ListHit { HeadVar = va + (ulong)i, How = $"{sec.Name}+0x{i:X}" };
                var cur = rec;
                int guard = 0;
                while (cur is not null && guard++ < 64)
                {
                    if (!seen.Add(cur.Address)) break;
                    hit.Chain.Add(cur);
                    result.Add(cur);
                    AgentRecord? next = null;
                    foreach (ulong q in cur.Pointers)
                    {
                        if (seen.Contains(q)) continue;
                        next = JvmtiAgentProbe.TryRead(ctx, q, requireHard: false);
                        if (next is not null) break;
                    }
                    cur = next;
                }
                if (hit.Chain.Count > 0) hits.Add(hit);
                if (hits.Count > 8) break;
            }
            if (hits.Count > 8) break;
        }

        if (hits.Count == 0)
        {
            sb.AppendLine(L("  list head not found: jvm.dll data has no pointer to an object that parses as an agent record.", "  no se encontró la cabeza de la lista: los datos de jvm.dll no tienen ningún puntero a un objeto que se analice como registro de agente."));
            sb.AppendLine(L("  IMPORTANT: this does not yet mean there were no agents. The list could have been cleared manually and the record freed. That is why the whole process heap is scanned independently below.", "  IMPORTANTE: esto aún no significa que no hubiera agentes. La lista pudo vaciarse a mano y el registro liberarse. Por eso más abajo se revisa de forma independiente todo el heap del proceso."));
            sb.AppendLine();
            FindOrphanAgents(ctx, jvm, result, sb);
            return result;
        }

        foreach (var h in hits)
        {
            sb.AppendLine(L($"  head 0x{h.HeadVar:X} (jvm.dll {h.How}) → chain of {h.Chain.Count} records", $"  cabeza 0x{h.HeadVar:X} (jvm.dll {h.How}) → cadena de {h.Chain.Count} registros"));
            foreach (var a in h.Chain)
                sb.AppendLine(L($"      0x{a.Address:X}  «{a.Name}»  options: {(a.Options is null ? "-" : "«" + a.Options + "»")}  {a.HowLoaded}", $"      0x{a.Address:X}  «{a.Name}»  opciones: {(a.Options is null ? "-" : "«" + a.Options + "»")}  {a.HowLoaded}"));
        }
        sb.AppendLine();
        FindOrphanAgents(ctx, jvm, result, sb);
        return result;
    }

    private static void FindOrphanAgents(ScanContext ctx, ImageInMemory jvm,
        List<AgentRecord> known, StringBuilder sb)
    {
        var have = known.Select(a => a.Address).ToHashSet();
        var found = new List<AgentRecord>();

        var strings = new Dictionary<ulong, string>();
        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateAnyData, overlap: 512))
        {
            if (strings.Count > 20000) break;
            var r = ch.Region;
            var buf = ch.Exact;
            ulong rbase = ch.Base;

            foreach (var ext in new[] { ".dll"u8.ToArray(), ".so"u8.ToArray() })
            {
                int pos = 0;
                while (pos < buf.Length && strings.Count <= 20000)
                {
                    int idx = buf.AsSpan(pos).IndexOf(ext);
                    if (idx < 0) break;
                    int at = pos + idx;
                    pos = at + ext.Length;
                    if (at + ext.Length >= buf.Length || buf[at + ext.Length] != 0) continue;

                    int start = at;
                    while (start > 0 && buf[start - 1] is >= 0x20 and < 0x7F &&
                           at - start < 300) start--;
                    if (at + ext.Length - start < 5) continue;
                    strings[rbase + (ulong)start] =
                        Encoding.ASCII.GetString(buf, start, at + ext.Length - start);
                }
            }
        }

        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateData, overlap: 0x60))
        {
            if (found.Count >= 32) break;
            var r = ch.Region;
            var buf = ch.Exact;
            ulong rbase = ch.Base;

            for (int i = 0; i + 8 <= buf.Length; i += 8)
            {
                ulong v = BitConverter.ToUInt64(buf, i);
                if (v == 0 || !strings.ContainsKey(v)) continue;

                for (int back = 0; back <= 0x50; back += 8)
                {
                    if (i - back < 0) break;
                    ulong addr = rbase + (ulong)(i - back);
                    if (!have.Add(addr)) continue;
                    var rec = JvmtiAgentProbe.TryRead(ctx, addr);
                    if (rec is null) continue;
                    var dup = found.FirstOrDefault(x =>
                        x.OsLibPath is not null && x.OsLibPath == rec.OsLibPath);
                    if (dup is not null)
                    {
                        if (rec.Layout.Count <= dup.Layout.Count) break;
                        found.Remove(dup);
                        known.Remove(dup);
                    }
                    found.Add(rec);
                    known.Add(rec);
                    break;
                }
                if (found.Count >= 32) break;
            }
        }

        sb.AppendLine(L($"Strings resembling a library path in the heap: {strings.Count}", $"Cadenas parecidas a una ruta de biblioteca en el heap: {strings.Count}"));
        sb.AppendLine(L($"Agent records found outside the list: {found.Count}", $"Registros de agentes encontrados fuera de la lista: {found.Count}"));
        foreach (var a in found)
            sb.AppendLine(L($"    0x{a.Address:X}  «{a.Name}»  library: {(a.OsLibModule ?? (a.OsLib == 0 ? "-" : $"0x{a.OsLib:X} (no module)"))}", $"    0x{a.Address:X}  «{a.Name}»  biblioteca: {(a.OsLibModule ?? (a.OsLib == 0 ? "-" : $"0x{a.OsLib:X} (sin módulo)"))}"));
        sb.AppendLine();
        _ = jvm;
    }

    private static void ReportAgents(ScanContext ctx, List<AgentRecord> raw, StringBuilder sb)
    {
        var unique = raw
            .GroupBy(a => a.OsLibPath ?? $"@0x{a.OsLib:X}|{a.Name}|{a.Options}")
            .Select(g =>
            {
                var best = g.OrderByDescending(x => x.Layout.Count)
                            .ThenByDescending(x => x.Options is not null ? 1 : 0).First();
                if (g.Count() > 1)
                    best.Notes.Add(L($"the same record was identified at {g.Count()} offsets of the parse window (addresses: ", $"el mismo registro se identificó en {g.Count()} desplazamientos de la ventana de análisis (direcciones: ") +
                                   string.Join(", ", g.Select(x => $"0x{x.Address:X}").Take(6)) +
                                   ")");
                return best;
            })
            .ToList();

        var agents = unique.Where(a => a.OsLibPath is not null).ToList();
        var weak = unique.Where(a => a.OsLibPath is null).ToList();

        if (weak.Count > 0)
        {
            sb.AppendLine(L($"Structures with an agent record layout but no library path: {weak.Count} (not reported as findings — nothing is claimed about them)", $"Estructuras con disposición de registro de agente pero sin ruta de biblioteca: {weak.Count} (no se reportan como hallazgos: no se afirma nada sobre ellas)"));
            foreach (var a in weak.Take(12))
                sb.AppendLine(L($"    0x{a.Address:X}  handle 0x{a.OsLib:X}", $"    0x{a.Address:X}  handle 0x{a.OsLib:X}") +
                              (a.OsLibModule is not null ? $" → {a.OsLibModule}" : "") +
                              (a.Name is not null ? L($"  name «{a.Name}»", $"  nombre «{a.Name}»") : ""));
            sb.AppendLine();
        }

        sb.AppendLine(L("RECOVERED AGENT RECORDS:", "REGISTROS DE AGENTES RECUPERADOS:"));
        if (agents.Count == 0)
        {
            sb.AppendLine(L("  no records found.", "  no se encontraron registros."));
            sb.AppendLine();
            ctx.Report.Report("JVM",
                L("No agent records found in HotSpot internal lists", "No se encontraron registros de agentes en las listas internas de HotSpot"),
                Severity.Info,
                L("The virtual machine keeps attached agents in its own list (JvmtiAgentList in JDK 21, Arguments::_agentList in earlier ones) and does not clear it when an agent is detached: the record survives both Agent_OnUnload and DisposeEnvironment. The search was done in two independent ways — from the list head in jvm.dll data and by a full structural scan of the heap — and found nothing. This is a negative result, and it matters: it means nobody attached to this VM through the normal agent mechanism.", "La máquina virtual guarda los agentes conectados en su propia lista (JvmtiAgentList en JDK 21, Arguments::_agentList en versiones anteriores) y no la vacía al desconectar un agente: el registro sobrevive tanto a Agent_OnUnload como a DisposeEnvironment. La búsqueda se hizo de dos formas independientes (desde la cabeza de la lista en los datos de jvm.dll y con una revisión estructural completa del heap) y no encontró nada. Es un resultado negativo, y es importante: significa que nadie se conectó a esta VM mediante el mecanismo normal de agentes."));
            return;
        }

        foreach (var a in agents)
        {
            sb.AppendLine($"  ── 0x{a.Address:X}");
            sb.AppendLine(L($"     agent name           : {a.Name ?? "-"}", $"     nombre del agente      : {a.Name ?? "-"}"));
            sb.AppendLine(L($"     agent options        : {a.Options ?? "-"}", $"     opciones del agente    : {a.Options ?? "-"}"));
            sb.AppendLine(L($"     library handle       : 0x{a.OsLib:X}", $"     handle de la biblioteca: 0x{a.OsLib:X}") +
                          (a.OsLibModule is not null ? $" → {a.OsLibModule}" : ""));
            sb.AppendLine(L($"     library path         : {a.OsLibPath ?? "-"}", $"     ruta de la biblioteca  : {a.OsLibPath ?? "-"}"));
            sb.AppendLine(L($"     JPLIS native part    : 0x{a.Jplis:X}", $"     parte nativa JPLIS     : 0x{a.Jplis:X}"));
            sb.AppendLine(L($"     attach method        : {a.HowLoaded}", $"     método de conexión     : {a.HowLoaded}"));
            sb.AppendLine(L($"     absolute path        : {(a.AbsolutePath ? "yes" : "no")}   static: {(a.StaticLib ? "yes" : "no")}   instrument: {(a.InstrumentLib ? "yes" : "no")}   loaded: {(a.Loaded ? "yes" : "no")}", $"     ruta absoluta          : {(a.AbsolutePath ? "sí" : "no")}   estática: {(a.StaticLib ? "sí" : "no")}   instrument: {(a.InstrumentLib ? "sí" : "no")}   cargado: {(a.Loaded ? "sí" : "no")}"));
            if (a.Layout.Count > 0)
            {
                sb.AppendLine(L("     recovered record layout:", "     disposición recuperada del registro:"));
                foreach (var l in a.Layout) sb.AppendLine($"        {l}");
            }
            foreach (var n in a.Notes) sb.AppendLine($"     ! {n}");
            sb.AppendLine();
        }

        foreach (var a in agents)
        {
            bool wellKnown = a.Name is not null &&
                (a.Name.Equals("instrument", StringComparison.OrdinalIgnoreCase) ||
                 a.Name.Equals("jdwp", StringComparison.OrdinalIgnoreCase) ||
                 a.Name.Contains("management", StringComparison.OrdinalIgnoreCase));

            Severity sev = a.Dynamic ? Severity.Critical
                : wellKnown ? Severity.High
                : Severity.Critical;

            var f = ctx.Report.Report("JVM",
                L($"HotSpot internal structures contain a record of the agent «{a.Name ?? Path.GetFileName(a.OsLibPath!)}» ({a.HowLoaded})", $"Las estructuras internas de HotSpot contienen un registro del agente «{a.Name ?? Path.GetFileName(a.OsLibPath!)}» ({a.HowLoaded})"),
                sev,
                L("This is a record from the virtual machine\'s OWN AGENT LIST. It is created when an agent attaches and is never removed: neither Agent_OnUnload nor DisposeEnvironment touches it, because the VM keeps the list until the process ends. That is why what remains nowhere else can be read here: the agent name, its options string and the library file path. ", "Es un registro de la PROPIA LISTA DE AGENTES de la máquina virtual. Se crea al conectar un agente y nunca se elimina: ni Agent_OnUnload ni DisposeEnvironment lo tocan, porque la VM conserva la lista hasta el final del proceso. Por eso aquí se lee lo que no queda en ningún otro sitio: el nombre del agente, su cadena de opciones y la ruta del archivo de la biblioteca. ") +
                (a.Dynamic
                    ? L("The «dynamic» flag means the agent attached not at VM startup but TO THE ALREADY RUNNING game through the Attach API. A launcher never does this: it is exactly how a cheat is brought into a running game.", "La bandera «dinámico» significa que el agente se conectó no al arrancar la VM, sino AL JUEGO YA EN EJECUCIÓN mediante la Attach API. Un launcher nunca hace esto: es exactamente como se introduce un cheat en un juego en marcha.")
                    : a.DynamicKnown
                    ? L("The agent is listed in the virtual machine startup arguments. This is not normal for a Minecraft client: the launcher does not attach agents.", "El agente figura en los argumentos de arranque de la máquina virtual. No es normal en un cliente de Minecraft: el launcher no conecta agentes.")
                    : L("The attach method cannot be determined from the record of this JDK release: it has no «dynamic» field. Look at the VM arguments and the attach mechanism objects.", "El método de conexión no puede determinarse a partir del registro de esta versión del JDK: no tiene el campo «dinámico». Revise los argumentos de la VM y los objetos del mecanismo attach.")) +
                (a.OsLib != 0 && a.OsLibModule is null
                    ? L(" The library handle is non-zero, but there is no module at this address any more — the agent library was UNLOADED while its record remained.", " El handle de la biblioteca no es cero, pero ya no hay ningún módulo en esa dirección: la biblioteca del agente se DESCARGÓ mientras su registro permaneció.")
                    : ""));
            f.Add(L("record address", "dirección del registro"), a.Address);
            f.Add(L("agent name", "nombre del agente"), a.Name ?? "-");
            f.Add(L("agent options", "opciones del agente"), a.Options ?? "-");
            f.Add(L("library path", "ruta de la biblioteca"), a.OsLibPath ?? "-");
            f.Add(L("library handle", "handle de la biblioteca"), a.OsLib == 0 ? L("0 (not loaded)", "0 (no cargada)")
                : $"0x{a.OsLib:X}" + (a.OsLibModule is not null
                    ? $" → {a.OsLibModule}" : L(" → there is NO module with this base now", " → ahora NO hay ningún módulo con esta base")));
            f.Add(L("attached dynamically", "conectado dinámicamente"), !a.DynamicKnown
                ? L("cannot be determined (JDK records before 21 have no such field)", "no se puede determinar (los registros de JDK anteriores a 21 no tienen este campo)")
                : a.Dynamic ? L("YES (Attach API)", "SÍ (Attach API)") : L("no (startup argument)", "no (argumento de arranque)"));
            f.Add(L("java.lang.instrument library", "biblioteca java.lang.instrument"), a.InstrumentLib ? L("yes", "sí") : L("no", "no"));
            f.Add(L("loaded now", "cargado ahora"), a.Loaded ? L("yes", "sí") : L("no", "no"));
            f.Add(L("JPLIS pointer", "puntero JPLIS"), a.Jplis == 0 ? "-" : $"0x{a.Jplis:X}");
            if (a.Layout.Count > 0)
                f.Block(L("Recovered record layout (identified by the nature of the fields, not by fixed offsets)", "Disposición recuperada del registro (identificada por la naturaleza de los campos, no por desplazamientos fijos)"),
                    string.Join("\n", a.Layout.Select(x => "  " + x)));
            if (a.Dump is not null)
                f.Block(L("Record object", "Objeto del registro"), HexDump.Format(a.Dump, a.Address));
            foreach (var n in a.Notes) f.Add(L("note", "observación"), n);

            if (ctx.Dumper is not null)
            {
                string? p = ctx.Dumper.DumpRange(a.Address > 0x200 ? a.Address - 0x200 : a.Address,
                    0x1000, "agentrec", L($"agent record «{a.Name}» and its neighbourhood", $"registro del agente «{a.Name}» y su entorno"));
                if (p is not null) f.Add(L("neighbourhood dump", "volcado del entorno"), p);
            }
        }
    }

    private static readonly (string Cls, bool AlwaysPresent, string Why)[] AttachClasses =
    {
        ("AttachOperation", true,
            L("An operation object that came into the virtual machine FROM OUTSIDE through the attach mechanism (Attach API). Such an object is created for every command: «load» to load an agent, «properties», «threaddump» and others. The command name and its arguments lie in the object itself.", "Un objeto de operación que llegó a la máquina virtual DESDE FUERA mediante el mecanismo attach (Attach API). Se crea un objeto así por cada comando: «load» para cargar un agente, «properties», «threaddump» y otros. El nombre del comando y sus argumentos están en el propio objeto.")),
        ("Win32AttachOperation", true,
            L("The Windows implementation of an attach operation: the command arrives through a named pipe created by the attach mechanism. IMPORTANT for interpretation: on Windows the command listener always starts together with the virtual machine and pre-allocates several such objects for the queue. Verified on a clean Minecraft client: empty objects with «<noname>» and «<nopipe>» placeholders exist in any game and are not evidence. A FILLED command name is evidence.", "La implementación para Windows de una operación attach: el comando llega por una tubería con nombre que crea el mecanismo attach. IMPORTANTE para la interpretación: en Windows el receptor de comandos siempre arranca junto con la máquina virtual y reserva de antemano varios de estos objetos para la cola. Comprobado en un cliente de Minecraft limpio: los objetos vacíos con los marcadores «<noname>» y «<nopipe>» existen en cualquier partida y no son una prueba. Un nombre de comando RELLENO sí lo es.")),
        ("JVMTIAgentLoadDCmd", false,
            L("The jcmd command «JVMTI.agent_load» — loading an agent library into an already running virtual machine on external request. The object of the command itself (not its factory) is created only at execution time: a normal Minecraft client does not receive such commands.", "El comando jcmd «JVMTI.agent_load»: carga de una biblioteca de agente en una máquina virtual ya en ejecución a petición externa. El objeto del propio comando (no su fábrica) solo se crea al ejecutarlo: un cliente de Minecraft normal no recibe estos comandos.")),
        ("JVMTIDataDumpDCmd", false,
            L("The jcmd command «JVMTI.data_dump» — a request for a JVMTI data dump. The command object is created only when it is executed.", "El comando jcmd «JVMTI.data_dump»: petición de un volcado de datos JVMTI. El objeto del comando solo se crea al ejecutarlo.")),
    };

    private static readonly string[] AttachCommands =
    {
        "load", "properties", "agentProperties", "datadump", "threaddump",
        "dumpheap", "inspectheap", "setflag", "printflag", "jcmd", "jvmtiagentload",
        "JVMTI.agent_load",
    };

    private static void FindAttachOperations(ScanContext ctx, ImageInMemory jvm, StringBuilder sb)
    {
        sb.AppendLine(L("ATTACH MECHANISM OBJECTS (search by the exact vtable address from exports):", "OBJETOS DEL MECANISMO ATTACH (búsqueda por la dirección exacta de la vtable de las exportaciones):"));

        var wanted = new Dictionary<ulong, string>();
        foreach (var (cls, _, _) in AttachClasses)
        {
            var e = jvm.Pe.Exports.ByName($"??_7{cls}@@6B@");
            if (e is null)
            {
                sb.AppendLine(L($"  {cls,-28} virtual function table not exported", $"  {cls,-28} tabla de funciones virtuales no exportada"));
                continue;
            }
            ulong vt = jvm.Base + e.Rva;
            wanted[vt] = cls;
            sb.AppendLine($"  {cls,-28} vtable 0x{vt:X}");
        }
        if (wanted.Count == 0) { sb.AppendLine(); return; }

        var found = new Dictionary<string, List<ulong>>(StringComparer.Ordinal);
        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateAnyData))
        {
            var r = ch.Region;
            var buf = ch.Exact;
            ulong rbase = ch.Base;

            for (int i = 0; i + 8 <= buf.Length; i += 8)
            {
                ulong v = BitConverter.ToUInt64(buf, i);
                if (v == 0 || !wanted.TryGetValue(v, out var cls)) continue;
                if (!found.TryGetValue(cls, out var list)) found[cls] = list = new List<ulong>();
                if (list.Count < 64) list.Add(rbase + (ulong)i);
            }
        }

        foreach (var (cls, alwaysPresent, why) in AttachClasses)
        {
            if (!found.TryGetValue(cls, out var list) || list.Count == 0)
            {
                if (wanted.ContainsValue(cls)) sb.AppendLine(L($"  {cls,-28} no objects found", $"  {cls,-28} no se encontraron objetos"));
                continue;
            }

            sb.AppendLine(L($"  {cls,-28} objects FOUND: {list.Count}", $"  {cls,-28} objetos ENCONTRADOS: {list.Count}"));

            var filled = new List<(ulong Addr, string Cmd, List<string> Strings)>();
            var empty = new List<(ulong Addr, List<string> Strings)>();
            foreach (ulong a in list)
            {
                var strings = HarvestObjectStrings(ctx, a);
                string? cmd = strings.FirstOrDefault(s =>
                    AttachCommands.Contains(s, StringComparer.OrdinalIgnoreCase));
                if (cmd is not null) filled.Add((a, cmd, strings));
                else empty.Add((a, strings));
                sb.AppendLine($"      0x{a:X}  {ctx.RegionAt(a)?.TypeString}/" +
                              $"{ctx.RegionAt(a)?.ProtectString}" +
                              (cmd is not null ? L($"   COMMAND: «{cmd}»", $"   COMANDO: «{cmd}»") : L("   (command name is empty)", "   (el nombre del comando está vacío)")));
                if (strings.Count > 0)
                    sb.AppendLine(L("          strings inside the object: ", "          cadenas dentro del objeto: ") +
                                  string.Join(" | ", strings.Take(8)));
            }

            Severity sev = filled.Count > 0 ? Severity.Critical
                : alwaysPresent ? Severity.Info
                : Severity.High;

            string title = filled.Count > 0
                ? L($"{filled.Count} {cls} objects WITH A FILLED command name were found in memory ({string.Join(", ", filled.Select(x => x.Cmd).Distinct())}) — commands came to the running virtual machine from outside", $"Se encontraron en memoria {filled.Count} objetos {cls} CON el nombre de comando RELLENO ({string.Join(", ", filled.Select(x => x.Cmd).Distinct())}): llegaron comandos externos a la máquina virtual en ejecución")
                : L($"{list.Count} {cls} objects without a filled command name were found in memory", $"Se encontraron en memoria {list.Count} objetos {cls} sin nombre de comando relleno");

            var f = ctx.Report.Report("JVM", title, sev,
                why + (filled.Count > 0
                    ? L(" Here the command name is FILLED: the object was not merely allocated for the queue but actually carried a command. The «load» command loads an agent library into the running game, and its argument contains the path to that library.", " Aquí el nombre del comando está RELLENO: el objeto no solo se reservó para la cola, sino que realmente llevó un comando. El comando «load» carga una biblioteca de agente en el juego en ejecución, y su argumento contiene la ruta a esa biblioteca.")
                    : L(" No object has a filled command name, so it does not count as evidence — given for reference.", " Ningún objeto tiene el nombre de comando relleno, así que no cuenta como prueba: se muestra como referencia.")));
            f.Add(L("class", "clase"), cls);
            f.Add(L("objects total", "objetos en total"), list.Count.ToString());
            f.Add(L("of them with a command name", "de ellos con nombre de comando"), filled.Count.ToString());

            foreach (var (a, cmd, strings) in filled.Take(16))
                f.Add(L($"object 0x{a:X}", $"objeto 0x{a:X}"), L($"command «{cmd}»; strings: ", $"comando «{cmd}»; cadenas: ") +
                                         string.Join(" | ", strings.Take(10)));
            foreach (var (a, strings) in empty.Take(8))
                f.Add(L($"object 0x{a:X} (empty)", $"objeto 0x{a:X} (vacío)"), strings.Count > 0
                    ? L("strings: ", "cadenas: ") + string.Join(" | ", strings.Take(6))
                    : ctx.RegionAt(a)?.ToString() ?? "-");

            ulong first = filled.Count > 0 ? filled[0].Addr : list[0];
            var dump = ctx.Target.ReadBytes(first, 512);
            if (dump is not null)
                f.Block(L($"Object 0x{first:X}", $"Objeto 0x{first:X}"), HexDump.Format(dump, first));
        }
        sb.AppendLine();
    }

    private static List<string> HarvestObjectStrings(ScanContext ctx, ulong addr)
    {
        var res = new List<string>();
        var d = ctx.Target.ReadBytes(addr, 0x200);
        if (d is null) return res;

        var sb = new StringBuilder();
        foreach (byte b in d)
        {
            if (b is >= 0x20 and < 0x7F) sb.Append((char)b);
            else
            {
                if (sb.Length >= 3) res.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= 3) res.Add(sb.ToString());

        for (int i = 0; i + 8 <= d.Length; i += 8)
        {
            ulong p = BitConverter.ToUInt64(d, i);
            var s = JvmtiAgentProbe.ReadAscii(ctx, p, 256);
            if (s is { Length: >= 3 }) res.Add(s);
        }
        return res.Distinct().ToList();
    }

    private static readonly (string Needle, Severity Sev, string Why)[] AttachStrings =
    {
        ("JVMTI.agent_load", Severity.Info,
            L("The name of the command that loads an agent into a running VM (jcmd JVMTI.agent_load). The string gets into the heap when the diagnostic command registry is built at the startup of ANY virtual machine, so it is not evidence by itself — the command object matters, not its name.", "El nombre del comando que carga un agente en una VM en ejecución (jcmd JVMTI.agent_load). La cadena llega al heap al construirse el registro de comandos de diagnóstico al arrancar CUALQUIER máquina virtual, así que no es una prueba por sí sola: importa el objeto del comando, no su nombre.")),
        ("Dynamic agent loading", Severity.High,
            L("Part of the VM warning about dynamic agent loading: JDK 21 prints it when an agent attaches to a live VM.", "Parte del aviso de la VM sobre la carga dinámica de agentes: JDK 21 lo imprime cuando un agente se conecta a una VM en ejecución.")),
        ("A JVM TI agent has been loaded dynamically", Severity.Critical,
            L("A virtual machine warning printed EXACTLY ONCE — when a JVMTI agent is loaded dynamically into a running VM. The presence of this string in memory means such a load took place.", "Un aviso de la máquina virtual que se imprime EXACTAMENTE UNA VEZ: cuando un agente JVMTI se carga dinámicamente en una VM en ejecución. La presencia de esta cadena en memoria significa que esa carga ocurrió.")),
        ("-XX:+EnableDynamicAgentLoading", Severity.High,
            L("The flag that allows dynamic agent loading. Mentioned in the VM warning text and in the help; not evidence by itself, but comes in a pair.", "La opción que permite la carga dinámica de agentes. Aparece en el texto del aviso de la VM y en la ayuda; no es una prueba por sí sola, pero va en pareja.")),
        ("sun.jvm.hotspot", Severity.Info,
            L("Serviceability Agent package. The name is in the JDK module registry, so it occurs in the heap of any game — not evidence by itself.", "Paquete del Serviceability Agent. El nombre está en el registro de módulos del JDK, así que aparece en el heap de cualquier partida: no es una prueba por sí solo.")),
        ("com.sun.tools.attach", Severity.Info,
            L("Attach API package. The name is in the JDK module registry (module jdk.attach), so it occurs in the heap of any game. What matters is not the package name but classes loaded from it — the bytecode analysis checks those.", "Paquete de la Attach API. El nombre está en el registro de módulos del JDK (módulo jdk.attach), así que aparece en el heap de cualquier partida. Lo que importa no es el nombre del paquete, sino las clases cargadas de él, que comprueba el análisis de bytecode.")),
        ("\\\\.\\pipe\\javatool", Severity.Critical,
            L("The named pipe of the Windows attach mechanism: an external process passes commands to the running virtual machine through it.", "La tubería con nombre del mecanismo attach de Windows: a través de ella un proceso externo pasa comandos a la máquina virtual en ejecución.")),
        ("attach_listener", Severity.High,
            L("Internal name of the attach command listener thread.", "Nombre interno del hilo receptor de comandos attach.")),
    };

    private static void FindAgentStrings(ScanContext ctx, StringBuilder sb)
    {
        sb.AppendLine(L("ATTACH MECHANISM STRINGS IN PROCESS MEMORY:", "CADENAS DEL MECANISMO ATTACH EN LA MEMORIA DEL PROCESO:"));

        var hits = new Dictionary<string, List<ulong>>(StringComparer.Ordinal);
        var needles = AttachStrings
            .Select(x => (x.Needle, Bytes: Encoding.ASCII.GetBytes(x.Needle)))
            .ToList();

        foreach (var ch in MemoryScan.Chunks(ctx,
                     r0 => MemoryScan.Readable(r0) && r0.IsPrivate && !r0.IsImage &&
                           r0.MappedFile is null && r0.MappedFileDos is null, overlap: 64))
        {
            var r = ch.Region;
            var buf = ch.Exact;
            ulong rbase = ch.Base;

            foreach (var (needle, bytes) in needles)
            {
                int pos = 0;
                while (pos < buf.Length)
                {
                    int idx = buf.AsSpan(pos).IndexOf(bytes);
                    if (idx < 0) break;
                    if (!hits.TryGetValue(needle, out var list)) hits[needle] = list = new List<ulong>();
                    if (list.Count < 32) list.Add(rbase + (ulong)(pos + idx));
                    pos += idx + bytes.Length;
                    if (list.Count >= 32) break;
                }
            }
        }

        foreach (var (needle, sev, why) in AttachStrings)
        {
            hits.TryGetValue(needle, out var list);
            int n = list?.Count ?? 0;
            sb.AppendLine(L($"  {needle,-46} {(n == 0 ? "no" : $"FOUND ×{n}")}", $"  {needle,-46} {(n == 0 ? "no" : $"ENCONTRADA ×{n}")}"));
            if (n == 0) continue;

            var f = ctx.Report.Report("JVM",
                L($"The string «{needle}» was found in process memory ({n} occurrences in private memory)", $"Se encontró la cadena «{needle}» en la memoria del proceso ({n} apariciones en memoria privada)"),
                sev, why + L(" The string was found in the PRIVATE memory of the process — not in a module image and not in a JDK file mapping, but in working data: running code put it there.", " La cadena se encontró en la memoria PRIVADA del proceso, no en la imagen de un módulo ni en una proyección de un archivo del JDK, sino en datos de trabajo: la puso ahí el código en ejecución."));
            foreach (ulong a in (list ?? new List<ulong>()).Take(16))
            {
                var ctxBytes = ctx.Target.ReadBytes(a > 64 ? a - 64 : a, 192);
                f.Add($"0x{a:X}", ctx.RegionAt(a)?.ToString() ?? "-");
                if (ctxBytes is not null && f.Blocks.Count < 6)
                    f.Block(L($"Neighbourhood 0x{a:X}", $"Entorno de 0x{a:X}"),
                        HexDump.Format(ctxBytes, a > 64 ? a - 64 : a));
            }
        }
        sb.AppendLine();
    }
}
