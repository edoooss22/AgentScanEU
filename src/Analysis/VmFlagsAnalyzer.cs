using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class VmFlagsAnalyzer
{
    private static readonly string[] OriginNames =
    {
        L("default value", "valor por defecto"),
        L("command line", "línea de comandos"),
        L("environment variable", "variable de entorno"),
        L("settings file", "archivo de configuración"),
        L("management interface", "interfaz de gestión"),
        L("ergonomics (chosen by the VM)", "ergonomía (elegido por la VM)"),
        L("ATTACH ON DEMAND", "CONEXIÓN EN CALIENTE"),
        L("internal assignment", "asignación interna"),
        L("JDK image resource", "recurso de la imagen del JDK"),
    };

    private const uint OriginMask = 0xF;
    private const uint OriginDefault = 0;
    private const uint OriginCommandLine = 1;
    private const uint OriginEnviron = 2;
    private const uint OriginConfigFile = 3;
    private const uint OriginManagement = 4;
    private const uint OriginErgonomic = 5;
    private const uint OriginAttachOnDemand = 6;

    private static readonly string[] Sensitive =
    {
        "EnableDynamicAgentLoading", "DisableAttachMechanism", "StartAttachListener",
        "AllowRedefinitionToAddDeleteMethods", "TraceRedefineClasses",
        "UnlockDiagnosticVMOptions", "UnlockExperimentalVMOptions",
        "PrintFlagsFinal", "HeapDumpOnOutOfMemoryError", "HeapDumpPath",
        "OnError", "OnOutOfMemoryError", "AbortVMOnException", "ErrorFile",
        "LogFile", "LogVMOutput", "DisplayVMOutput", "UseSharedSpaces",
        "SharedArchiveFile", "ExtendedDTraceProbes", "FlightRecorderOptions",
        "StartFlightRecording", "NativeMemoryTracking", "PerfDisableSharedMem",
        "UsePerfData", "CreateCoredumpOnCrash", "ShowMessageBoxOnError",
        "MaxJavaStackTraceDepth", "OmitStackTraceInFastThrow",
    };

    private sealed class FlagRec
    {
        public string Name = "";
        public int Type;
        public uint Raw;
        public ulong ValueAddr;
        public string Value = "";
        public uint Origin => Raw & OriginMask;
        public bool WasSetOnCommandLine => (Raw & (1u << 17)) != 0;
    }

    public static void Run(ScanContext ctx)
    {
        var vm = ctx.Vm;
        var sb = new StringBuilder();
        sb.AppendLine(L("VIRTUAL MACHINE FLAGS: VALUE AND ORIGIN", "BANDERAS DE LA MÁQUINA VIRTUAL: VALOR Y ORIGEN"));
        sb.AppendLine();

        if (vm is null || !vm.Valid)
        {
            sb.AppendLine(L("  HotSpot structure layout not parsed — check skipped.", "  disposición de estructuras HotSpot no analizada: comprobación omitida."));
            ctx.Report.Section(L("VIRTUAL MACHINE FLAGS", "BANDERAS DE LA MÁQUINA VIRTUAL"), sb.ToString());
            return;
        }

        var c = new PageCache(ctx.Target, 8192);

        var args = ReadArguments(ctx, vm, c, sb);

        var flags = ReadFlags(vm, c, sb);
        if (flags.Count == 0)
        {
            ctx.Report.Section(L("VIRTUAL MACHINE FLAGS", "BANDERAS DE LA MÁQUINA VIRTUAL"), sb.ToString());
            return;
        }

        bool trusted = SelfCheck(flags, args.CmdFlagNames, sb);

        Census(flags, sb);
        ReportOrigins(ctx, flags, trusted, sb);
        ReportSensitive(ctx, flags, args, sb);
        ReportArgumentMismatch(ctx, args, flags, trusted, sb);

        ctx.Report.Section(L("VIRTUAL MACHINE FLAGS", "BANDERAS DE LA MÁQUINA VIRTUAL"), sb.ToString());
    }

    private static List<FlagRec> ReadFlags(VmStructs vm, PageCache c, StringBuilder sb)
    {
        var res = new List<FlagRec>();

        ulong arrPtr = vm.StaticAddr("JVMFlag", "flags");
        ulong numPtr = vm.StaticAddr("JVMFlag", "numFlags");
        int size = (int)vm.TypeSize("JVMFlag");
        int oAddr = vm.Off("JVMFlag", "_addr");
        int oName = vm.Off("JVMFlag", "_name");
        int oFlags = vm.Off("JVMFlag", "_flags");
        int oType = vm.Off("JVMFlag", "_type");

        if (arrPtr == 0 || numPtr == 0 || size <= 0 || oAddr < 0 || oName < 0 || oFlags < 0)
        {
            sb.AppendLine(L("  the flag table is not described in this build (no JVMFlag::flags / numFlags / entry fields) — check skipped.", "  la tabla de banderas no está descrita en esta compilación (no hay JVMFlag::flags / numFlags / campos de entrada): comprobación omitida."));
            sb.AppendLine();
            return res;
        }

        ulong arr = c.U64(arrPtr);
        ulong n = c.U64(numPtr);
        sb.AppendLine(L($"  flag table                  : 0x{arr:X}, entries {n}, entry size {size} bytes", $"  tabla de banderas           : 0x{arr:X}, entradas {n}, tamaño de entrada {size} bytes"));
        if (arr is < 0x10000 or > 0x7FFFFFFFFFFFFF || n is 0 or > 20000)
        {
            sb.AppendLine(L("  table address or length is implausible — check skipped.", "  la dirección o la longitud de la tabla no son plausibles: comprobación omitida."));
            sb.AppendLine();
            return res;
        }

        for (ulong i = 0; i < n; i++)
        {
            ulong e = arr + i * (ulong)size;
            string name = ReadCStr(c, c.U64(e + (ulong)oName), 96);
            if (name.Length == 0) continue;

            var f = new FlagRec
            {
                Name = name,
                Raw = c.U32(e + (ulong)oFlags),
                Type = oType >= 0 ? (int)c.U32(e + (ulong)oType) : -1,
                ValueAddr = c.U64(e + (ulong)oAddr),
            };
            f.Value = FormatValue(c, f);
            res.Add(f);
        }

        sb.AppendLine(L($"  entries read                : {res.Count}", $"  entradas leídas             : {res.Count}"));
        sb.AppendLine();
        return res;
    }

    private static string FormatValue(PageCache c, FlagRec f)
    {
        ulong a = f.ValueAddr;
        if (a is < 0x1000 or > 0x7FFFFFFFFFFFFF) return L("<value address unavailable>", "<dirección del valor no disponible>");
        switch (f.Type)
        {
            case 0:
            {
                Span<byte> b = stackalloc byte[1];
                return c.Read(a, b) ? (b[0] != 0 ? "true" : "false") : "?";
            }
            case 1: return ((int)c.U32(a)).ToString();
            case 2: return c.U32(a).ToString();
            case 3: return ((long)c.U64(a)).ToString();
            case 4:
            case 5:
            case 6: return c.U64(a).ToString();
            case 7:
            {
                Span<byte> b = stackalloc byte[8];
                return c.Read(a, b) ? BitConverter.ToDouble(b).ToString("G6") : "?";
            }
            case 8:
            case 9:
            {
                ulong p = c.U64(a);
                string s = ReadCStr(c, p, 400);
                return s.Length > 0 ? "\"" + s + "\"" : (p == 0 ? L("<empty>", "<vacío>") : $"0x{p:X}");
            }
            default: return L($"0x{c.U64(a):X} <type {f.Type} unknown>", $"0x{c.U64(a):X} <tipo {f.Type} desconocido>");
        }
    }

    private sealed class ArgsRec
    {
        public List<string> JvmArgs = new();
        public List<string> JvmFlags = new();
        public string JavaCommand = "";
        public HashSet<string> CmdFlagNames = new(StringComparer.Ordinal);
        public bool Read;
    }

    private static ArgsRec ReadArguments(ScanContext ctx, VmStructs vm, PageCache c,
        StringBuilder sb)
    {
        var r = new ArgsRec();
        sb.AppendLine(L("THE VIRTUAL MACHINE\'S OWN COPY OF ITS ARGUMENTS", "COPIA PROPIA DE LOS ARGUMENTOS DE LA MÁQUINA VIRTUAL"));

        ulong pArgs = vm.StaticAddr("Arguments", "_jvm_args_array");
        ulong pNArgs = vm.StaticAddr("Arguments", "_num_jvm_args");
        ulong pFlags = vm.StaticAddr("Arguments", "_jvm_flags_array");
        ulong pNFlags = vm.StaticAddr("Arguments", "_num_jvm_flags");
        ulong pCmd = vm.StaticAddr("Arguments", "_java_command");

        if (pArgs == 0 || pNArgs == 0)
        {
            sb.AppendLine(L("  Arguments fields are not described in this build — the copy is unavailable.", "  los campos de Arguments no están descritos en esta compilación: la copia no está disponible."));
            sb.AppendLine();
            return r;
        }
        r.Read = true;
        r.JvmArgs = ReadStrArray(c, c.U64(pArgs), (int)c.U32(pNArgs));
        if (pFlags != 0 && pNFlags != 0)
            r.JvmFlags = ReadStrArray(c, c.U64(pFlags), (int)c.U32(pNFlags));
        if (pCmd != 0) r.JavaCommand = ReadCStr(c, c.U64(pCmd), 1024);

        foreach (string a in r.JvmArgs.Concat(r.JvmFlags))
        {
            string? nm = FlagNameOf(a);
            if (nm is not null) r.CmdFlagNames.Add(nm);
            foreach (string implied in ImpliedFlags(a)) r.CmdFlagNames.Add(implied);
        }

        sb.AppendLine(L($"  VM arguments                : {r.JvmArgs.Count}", $"  argumentos de la VM         : {r.JvmArgs.Count}"));
        foreach (string a in r.JvmArgs) sb.AppendLine("      " + a);
        if (r.JvmFlags.Count > 0)
        {
            sb.AppendLine(L($"  from settings file (-XX:Flags): {r.JvmFlags.Count}", $"  del archivo de configuración (-XX:Flags): {r.JvmFlags.Count}"));
            foreach (string a in r.JvmFlags) sb.AppendLine("      " + a);
        }
        sb.AppendLine(L($"  main class and its arguments:", $"  clase principal y sus argumentos:"));
        sb.AppendLine("      " + JavaMeta.Clean(r.JavaCommand, 900));
        sb.AppendLine();

        ReportAgentArguments(ctx, r);
        ReportCommandLineDivergence(ctx, r, sb);
        return r;
    }

    private static IEnumerable<string> ImpliedFlags(string arg)
    {
        if (arg.StartsWith("-Xmx", StringComparison.Ordinal))
            return new[] { "MaxHeapSize", "SoftMaxHeapSize", "MaxNewSize" };
        if (arg.StartsWith("-Xms", StringComparison.Ordinal))
            return new[] { "InitialHeapSize", "MinHeapSize" };
        if (arg.StartsWith("-Xss", StringComparison.Ordinal))
            return new[] { "ThreadStackSize" };
        if (arg.StartsWith("-Xmn", StringComparison.Ordinal))
            return new[] { "NewSize", "MaxNewSize" };
        if (arg.StartsWith("-Xnoclassgc", StringComparison.Ordinal))
            return new[] { "ClassUnloading", "ClassUnloadingWithConcurrentMark" };
        if (arg.StartsWith("-Xbatch", StringComparison.Ordinal))
            return new[] { "BackgroundCompilation" };
        if (arg.StartsWith("-Xint", StringComparison.Ordinal))
            return new[] { "UseCompiler", "UseInterpreter" };
        if (arg.StartsWith("-Xcomp", StringComparison.Ordinal))
            return new[] { "UseCompiler", "CompileThreshold", "BackgroundCompilation" };
        if (arg.StartsWith("-Xrs", StringComparison.Ordinal))
            return new[] { "ReduceSignalUsage" };
        if (arg.StartsWith("-Xshare", StringComparison.Ordinal))
            return new[] { "UseSharedSpaces", "RequireSharedSpaces" };
        if (arg.StartsWith("-XX:MaxTenuringThreshold", StringComparison.Ordinal))
            return new[] { "AlwaysTenure", "NeverTenure" };
        if (arg.StartsWith("-XX:InitialTenuringThreshold", StringComparison.Ordinal))
            return new[] { "AlwaysTenure", "NeverTenure" };
        if (arg.StartsWith("-Xlog", StringComparison.Ordinal))
            return new[] { "LogVMOutput", "DisplayVMOutput", "LogFile" };
        return Array.Empty<string>();
    }

    private static string? FlagNameOf(string arg)
    {
        if (!arg.StartsWith("-XX:", StringComparison.Ordinal)) return null;
        string s = arg[4..];
        if (s.Length == 0) return null;
        if (s[0] is '+' or '-') s = s[1..];
        int eq = s.IndexOf('=');
        if (eq >= 0) s = s[..eq];
        return s.Length > 0 ? s : null;
    }

    private static void ReportAgentArguments(ScanContext ctx, ArgsRec r)
    {
        string[] markers =
        {
            "-javaagent:", "-agentlib:", "-agentpath:", "-Xbootclasspath",
            "-Xrunjdwp", "-agentlib:jdwp", "-XX:+EnableDynamicAgentLoading",
            "-Xshare:off", "-XX:TraceClassLoading",
        };
        var hits = r.JvmArgs.Concat(r.JvmFlags)
            .Where(a => markers.Any(m => a.StartsWith(m, StringComparison.OrdinalIgnoreCase)))
            .ToList();
        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            L($"The virtual machine was started with {hits.Count} arguments that load foreign code", $"La máquina virtual se inició con {hits.Count} argumentos que cargan código ajeno"),
            Severity.Critical,
            L("The -javaagent / -agentlib / -agentpath arguments attach a foreign library or agent to the virtual machine before the game starts. The Minecraft launcher does not set such arguments. The list was read from the virtual machine\'s OWN copy of its arguments (Arguments::_jvm_args_array), not from the process command line: the copy is made when the VM is created and cannot be replaced after startup, whereas the command line in the environment block can be rewritten.", "Los argumentos -javaagent / -agentlib / -agentpath conectan una biblioteca o un agente ajeno a la máquina virtual antes de que arranque el juego. El launcher de Minecraft no pone estos argumentos. La lista se leyó de la PROPIA copia de argumentos de la máquina virtual (Arguments::_jvm_args_array), no de la línea de comandos del proceso: la copia se hace al crear la VM y no puede sustituirse después del arranque, mientras que la línea de comandos del bloque de entorno sí puede reescribirse."));
        foreach (string h in hits) f.Add(L("argument", "argumento"), h);
    }

    private static void ReportCommandLineDivergence(ScanContext ctx, ArgsRec r, StringBuilder sb)
    {
        string? peb = ctx.Target.GetCommandLine();
        sb.AppendLine(L("COMPARISON WITH THE PROCESS COMMAND LINE (environment block)", "COMPARACIÓN CON LA LÍNEA DE COMANDOS DEL PROCESO (bloque de entorno)"));
        if (string.IsNullOrEmpty(peb))
        {
            sb.AppendLine(L("  process command line not read — comparison skipped.", "  no se leyó la línea de comandos del proceso: comparación omitida."));
            sb.AppendLine();
            return;
        }

        var missing = r.JvmArgs
            .Where(a => a.Length > 3 && !peb.Contains(a, StringComparison.Ordinal))
            .ToList();
        sb.AppendLine(L($"  VM arguments missing from the process command line: {missing.Count}", $"  argumentos de la VM que faltan en la línea de comandos del proceso: {missing.Count}"));
        foreach (string mssng in missing.Take(40)) sb.AppendLine("      " + mssng);
        sb.AppendLine();
        if (missing.Count == 0) return;

        bool agentish = missing.Any(a =>
            a.StartsWith("-javaagent", StringComparison.OrdinalIgnoreCase) ||
            a.StartsWith("-agent", StringComparison.OrdinalIgnoreCase) ||
            a.StartsWith("-Xbootclasspath", StringComparison.OrdinalIgnoreCase));

        var f = ctx.Report.Report("JVM",
            L($"{missing.Count} virtual machine arguments are missing from the process command line", $"Faltan {missing.Count} argumentos de la máquina virtual en la línea de comandos del proceso"),
            agentish ? Severity.Critical : Severity.Low,
            L("The virtual machine keeps its own copy of the arguments it was created with. The process command line in the environment block is an independent record of the same thing. A mismatch means the arguments did not come from the command line: usually from the JAVA_TOOL_OPTIONS / _JAVA_OPTIONS / JDK_JAVA_OPTIONS environment variables used to slip a foreign payload past the launcher. A mismatch by itself is legitimate (some launchers work this way); what makes it evidence is the content of the differing arguments.", "La máquina virtual guarda su propia copia de los argumentos con los que se creó. La línea de comandos del proceso en el bloque de entorno es un registro independiente de lo mismo. Una discrepancia significa que los argumentos no vinieron de la línea de comandos: normalmente de las variables de entorno JAVA_TOOL_OPTIONS / _JAVA_OPTIONS / JDK_JAVA_OPTIONS, con las que se cuela una carga ajena eludiendo el launcher. La discrepancia por sí sola es legítima (algunos launchers funcionan así); lo que la convierte en prueba es el contenido de los argumentos que difieren."));
        foreach (string mssng in missing.Take(30)) f.Add(L("only in the VM copy", "solo en la copia de la VM"), mssng);
    }

    private static bool SelfCheck(List<FlagRec> flags, HashSet<string> cmdNames, StringBuilder sb)
    {
        sb.AppendLine(L("ORIGIN PARSING SELF-CHECK", "AUTOCOMPROBACIÓN DEL ANÁLISIS DEL ORIGEN"));
        var fromCmd = flags.Where(f => f.Origin == OriginCommandLine).Select(f => f.Name).ToList();
        if (cmdNames.Count == 0)
        {
            sb.AppendLine(L("  the VM argument copy is unavailable — nothing to verify the origin against; origin conclusions below are marked as unverified.", "  la copia de argumentos de la VM no está disponible: no hay con qué verificar el origen; las conclusiones sobre el origen de abajo se marcan como no verificadas."));
            sb.AppendLine();
            return false;
        }
        if (fromCmd.Count == 0)
        {
            sb.AppendLine(L($"  flags with origin «command line»: 0 with {cmdNames.Count} names in the arguments — parsing of the origin bits is not confirmed.", $"  banderas con origen «línea de comandos»: 0 con {cmdNames.Count} nombres en los argumentos: el análisis de los bits de origen no está confirmado."));
            sb.AppendLine();
            return false;
        }

        int hit = fromCmd.Count(cmdNames.Contains);
        double share = hit * 100.0 / fromCmd.Count;
        sb.AppendLine(L($"  flags with origin «command line»   : {fromCmd.Count}", $"  banderas con origen «línea de comandos» : {fromCmd.Count}"));
        sb.AppendLine(L($"  of them found among the VM arguments: {hit} ({share:F1} %)", $"  de ellas, encontradas en los argumentos de la VM: {hit} ({share:F1} %)"));
        var stray = fromCmd.Where(n => !cmdNames.Contains(n)).ToList();
        foreach (string s in stray.Take(20))
            sb.AppendLine(L($"      not among the arguments: {s}", $"      no están en los argumentos: {s}"));
        bool ok = share >= 60;
        sb.AppendLine(ok
            ? (share >= 90
                ? L("  parsing confirmed: the origin and command line records agree.", "  análisis confirmado: los registros de origen y de línea de comandos coinciden.")
                : L("  parsing confirmed: offsets and origin bits are correct; the remaining mismatch is due to aliases of short flags.", "  análisis confirmado: los desplazamientos y los bits de origen son correctos; la discrepancia restante se debe a alias de opciones cortas."))
            : L("  parsing NOT confirmed: less than three fifths matched — the entry layout or the bit interpretation is wrong, origin conclusions are disabled.", "  análisis NO confirmado: coincidió menos de tres quintos; la disposición de la entrada o la interpretación de los bits son erróneas y las conclusiones sobre el origen están desactivadas."));
        sb.AppendLine();
        return ok;
    }

    private static void Census(List<FlagRec> flags, StringBuilder sb)
    {
        sb.AppendLine(L("BREAKDOWN BY ORIGIN", "DESGLOSE POR ORIGEN"));
        var byOrigin = flags.GroupBy(f => f.Origin).OrderBy(g => g.Key);
        foreach (var g in byOrigin)
            sb.AppendLine($"  {OriginName(g.Key),-28} : {g.Count()}");
        sb.AppendLine();

        sb.AppendLine(L("ALL FLAGS WITH AN ORIGIN OTHER THAN «DEFAULT VALUE»", "TODAS LAS BANDERAS CON UN ORIGEN DISTINTO DE «VALOR POR DEFECTO»"));
        foreach (var f in flags.Where(x => x.Origin != OriginDefault)
                     .OrderBy(x => x.Origin).ThenBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine(L($"  {f.Name,-42} = {f.Value,-28} [{OriginName(f.Origin)}]{(f.WasSetOnCommandLine ? " (marked as set on the command line)" : "")}", $"  {f.Name,-42} = {f.Value,-28} [{OriginName(f.Origin)}]{(f.WasSetOnCommandLine ? " (marcada como definida en la línea de comandos)" : "")}"));
        sb.AppendLine();
    }

    private static string OriginName(uint o) =>
        o < OriginNames.Length ? OriginNames[o] : L($"origin {o}", $"origen {o}");

    private static void ReportOrigins(ScanContext ctx, List<FlagRec> flags, bool trusted,
        StringBuilder sb)
    {
        string caveat = trusted
            ? ""
            : L(" WARNING: the origin parsing self-check failed, the origin bits may be misinterpreted — verify manually.", " ATENCIÓN: la autocomprobación del análisis del origen falló; los bits de origen pueden interpretarse mal: verifique manualmente.");

        var attach = flags.Where(f => f.Origin == OriginAttachOnDemand).ToList();
        if (attach.Count > 0)
        {
            var f = ctx.Report.Report("JVM",
                L($"{attach.Count} virtual machine flags were changed by ATTACHING TO THE RUNNING VM", $"{attach.Count} banderas de la máquina virtual se cambiaron mediante una CONEXIÓN A LA VM EN EJECUCIÓN"),
                Severity.Critical,
                L("The virtual machine sets the «attach on demand» origin on a flag in exactly one case: someone attached to the already running process through the attach mechanism and executed a setting change command. The same mechanism is used to inject a JVMTI agent into the process (VirtualMachine.attach → loadAgent). The record lives in jvm.dll static data: detaching, unloading the agent and removing its classes do not touch it.", "La máquina virtual pone el origen «conexión en caliente» a una bandera en un único caso: alguien se conectó al proceso ya en ejecución mediante el mecanismo attach y ejecutó un comando de cambio de configuración. El mismo mecanismo sirve para inyectar un agente JVMTI en el proceso (VirtualMachine.attach → loadAgent). El registro vive en los datos estáticos de jvm.dll: la desconexión, la descarga del agente y el borrado de sus clases no lo tocan.") + caveat);
            foreach (var x in attach) f.Add(x.Name, x.Value);
        }

        var mgmt = flags.Where(f => f.Origin == OriginManagement).ToList();
        if (mgmt.Count > 0)
        {
            var f = ctx.Report.Report("JVM",
                L($"{mgmt.Count} virtual machine flags were changed through the management interface", $"{mgmt.Count} banderas de la máquina virtual se cambiaron mediante la interfaz de gestión"),
                Severity.High,
                L("The «management interface» origin is set when a setting is changed by HotSpotDiagnosticMXBean.setVMOption — that is, by code already inside the process that reached the virtual machine management interface. The game and its mods do not do this.", "El origen «interfaz de gestión» se pone cuando una configuración la cambia HotSpotDiagnosticMXBean.setVMOption, es decir, código que ya está dentro del proceso y que llegó a la interfaz de gestión de la máquina virtual. El juego y sus mods no hacen esto.") + caveat);
            foreach (var x in mgmt) f.Add(x.Name, x.Value);
        }

        var env = flags.Where(f => f.Origin is OriginEnviron or OriginConfigFile).ToList();
        if (env.Count > 0)
        {
            var f = ctx.Report.Report("JVM",
                L($"{env.Count} virtual machine flags came not from the command line but from an environment variable or settings file", $"{env.Count} banderas de la máquina virtual no vinieron de la línea de comandos, sino de una variable de entorno o un archivo de configuración"),
                Severity.Medium,
                L("The JAVA_TOOL_OPTIONS, _JAVA_OPTIONS and JDK_JAVA_OPTIONS variables and the -XX:Flags file are standard ways to set virtual machine settings past the launcher. They are also used to slip in -javaagent without touching the launch shortcut. Not evidence by itself (some launchers do exactly this), but the list must be explained.", "Las variables JAVA_TOOL_OPTIONS, _JAVA_OPTIONS y JDK_JAVA_OPTIONS y el archivo -XX:Flags son formas estándar de configurar la máquina virtual eludiendo el launcher. También se usan para colar -javaagent sin tocar el acceso directo de lanzamiento. No es una prueba por sí solo (algunos launchers hacen exactamente esto), pero la lista debe tener explicación.") + caveat);
            foreach (var x in env)
                f.Add(x.Name, $"{x.Value}  [{OriginName(x.Origin)}]");
        }
    }

    private static void ReportSensitive(ScanContext ctx, List<FlagRec> flags, ArgsRec args,
        StringBuilder sb)
    {
        var set = new HashSet<string>(Sensitive, StringComparer.Ordinal);
        var rows = flags.Where(f => set.Contains(f.Name)).ToList();

        sb.AppendLine(L("FLAGS RELATED TO ATTACHING AND CODE REPLACEMENT", "BANDERAS RELACIONADAS CON LA CONEXIÓN Y LA SUSTITUCIÓN DE CÓDIGO"));
        foreach (var f in rows.OrderBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine($"  {f.Name,-42} = {f.Value,-28} [{OriginName(f.Origin)}]");
        sb.AppendLine();

        var touched = rows
            .Where(f => f.Origin != OriginDefault && f.Origin != OriginErgonomic)
            .Where(f => !(f.Origin == OriginCommandLine && args.CmdFlagNames.Contains(f.Name)))
            .ToList();
        sb.AppendLine(L($"  of them set not by the launcher: {touched.Count}", $"  de ellas, no definidas por el launcher: {touched.Count}"));
        sb.AppendLine();
        if (touched.Count == 0) return;

        bool loud = touched.Any(f =>
            f.Name is "EnableDynamicAgentLoading" or "DisableAttachMechanism"
                or "AllowRedefinitionToAddDeleteMethods" or "StartAttachListener");

        var fnd = ctx.Report.Report("JVM",
            L($"{touched.Count} flags related to attaching foreign code are set explicitly (not default and not by ergonomics)", $"{touched.Count} banderas relacionadas con la conexión de código ajeno están definidas explícitamente (no por defecto ni por ergonomía)"),
            loud ? Severity.High : Severity.Medium,
            L("These settings control the mechanism for attaching to the virtual machine, on-the-fly class replacement and debug output. The game launcher does not set them. An explicitly set value means someone found it necessary to change them — and the value origin shows exactly who and when.", "Estas configuraciones controlan el mecanismo de conexión a la máquina virtual, la sustitución de clases en caliente y la salida de depuración. El launcher del juego no las define. Un valor definido explícitamente significa que alguien consideró necesario cambiarlas, y el origen del valor muestra exactamente quién y cuándo."));
        foreach (var f in touched)
            fnd.Add(f.Name, $"{f.Value}  [{OriginName(f.Origin)}]");
    }

    private static void ReportArgumentMismatch(ScanContext ctx, ArgsRec args,
        List<FlagRec> flags, bool trusted, StringBuilder sb)
    {
        if (!trusted || !args.Read || args.CmdFlagNames.Count == 0) return;

        var stray = flags
            .Where(f => f.Origin == OriginCommandLine && !args.CmdFlagNames.Contains(f.Name))
            .ToList();
        if (stray.Count == 0) return;

        var fnd = ctx.Report.Report("JVM",
            L($"{stray.Count} flags are marked as set on the command line, but they are missing from the virtual machine\'s own argument copy", $"{stray.Count} banderas están marcadas como definidas en la línea de comandos, pero faltan en la propia copia de argumentos de la máquina virtual"),
            stray.Count > 8 ? Severity.High : Severity.Low,
            L("The virtual machine keeps two independent records: the array of argument strings it was created with and the origin bits of every flag. When the command line is parsed, they are filled together and must agree. A flag marked as coming from the command line but missing from the arguments means the value was assigned bypassing argument parsing — directly into VM memory.", "La máquina virtual mantiene dos registros independientes: el array de cadenas de argumentos con el que se creó y los bits de origen de cada bandera. Al analizar la línea de comandos se rellenan juntos y deben coincidir. Una bandera marcada como procedente de la línea de comandos pero ausente de los argumentos significa que el valor se asignó eludiendo el análisis de argumentos: directamente en la memoria de la VM."));
        foreach (var f in stray.Take(40)) fnd.Add(f.Name, f.Value);
    }

    private static List<string> ReadStrArray(PageCache c, ulong arr, int n)
    {
        var res = new List<string>();
        if (arr is < 0x10000 or > 0x7FFFFFFFFFFFFF || n is <= 0 or > 4096) return res;
        for (int i = 0; i < n; i++)
        {
            string s = ReadCStr(c, c.U64(arr + (ulong)i * 8), 1024);
            if (s.Length > 0) res.Add(s);
        }
        return res;
    }

    private static string ReadCStr(PageCache c, ulong addr, int max)
    {
        if (addr is < 0x1000 or > 0x7FFFFFFFFFFFFF) return "";
        var b = c.Read(addr, max);
        if (b is null) return "";
        var sb = new StringBuilder();
        foreach (byte x in b)
        {
            if (x == 0) break;
            sb.Append(x is >= 32 and < 127 ? (char)x : '.');
        }
        return sb.ToString();
    }
}
