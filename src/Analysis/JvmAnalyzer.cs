using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal sealed class VmTable
{
    public ulong Address;
    public int Slots;
    public int NonNull;
    public int OutsideJvm;
    public List<(int Slot, ulong Target)> Foreign = new();
    public string Kind = "?";
    public RawPattern? RefPattern;
}

internal static class JvmAnalyzer
{
    private static readonly string[] AgentModules =
    {
        "instrument.dll", "jdwp.dll", "attach.dll", "management.dll", "management_ext.dll",
        "management_agent.dll", "jsig.dll"
    };

    private static readonly (string Name, Severity Sev, string Why)[] TellTaleThreads =
    {
        ("JVMTI Agent Thread", Severity.Critical,
            L("Service thread created through JVMTI RunAgentThread. Exists only while a JVMTI agent is active.", "Hilo de servicio creado mediante JVMTI RunAgentThread. Solo existe mientras hay un agente JVMTI activo.")),
        ("JDWP", Severity.High,
            L("JDWP debug transport thread — a debugger is attached to the JVM.", "Hilo del transporte de depuración JDWP: hay un depurador conectado a la JVM.")),
        ("Java Debug", Severity.High, L("JVM debugging infrastructure is active.", "La infraestructura de depuración de la JVM está activa.")),
        ("Attach Listener", Severity.Info,
            L("On Windows this thread is always created at JVM startup and is not evidence. What matters is different: if it was created noticeably later than the process start, the attach mechanism fired again.", "En Windows este hilo siempre se crea al arrancar la JVM y no es una prueba. Lo que importa es otra cosa: si se creó bastante después del inicio del proceso, el mecanismo attach se activó de nuevo.")),
    };

    public static ImageInMemory? FindJvm(ScanContext ctx) =>
        ctx.Images.FirstOrDefault(i => i.Name.Equals("jvm.dll", StringComparison.OrdinalIgnoreCase));

    public static List<VmTable> FindVmTables(ScanContext ctx)
    {
        var res = new List<VmTable>();
        var jvm = FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid) return res;

        ulong imgLo = jvm.Base, imgHi = jvm.Base + jvm.Size;
        var textSections = jvm.Pe.Sections.Where(s => s.IsExecutable).ToList();
        if (textSections.Count == 0) return res;

        bool InText(ulong p)
        {
            if (p < imgLo || p >= imgHi) return false;
            uint rva = (uint)(p - imgLo);
            return textSections.Any(s => rva >= s.VirtualAddress &&
                                         rva < s.VirtualAddress + s.VirtualSize);
        }

        foreach (var sec in jvm.Pe.Sections)
        {
            if (sec.IsExecutable) continue;
            if (sec.VirtualSize is 0 or > 64 * 1024 * 1024) continue;
            if (sec.Name is not (".rdata" or ".data")) continue;

            var buf = new byte[sec.VirtualSize];
            ctx.Target.ReadPartial(jvm.Base + sec.VirtualAddress, buf, out _);
            ulong secVa = jvm.Base + sec.VirtualAddress;

            var runs = new List<(int Start, int Slots, int NonNull)>();
            int i = 0;
            while (i + 8 <= buf.Length)
            {
                ulong v = BitConverter.ToUInt64(buf, i);
                if (v != 0 && !InText(v)) { i += 8; continue; }

                int start = i, nonNull = 0;
                while (i + 8 <= buf.Length)
                {
                    ulong x = BitConverter.ToUInt64(buf, i);
                    if (x == 0) { i += 8; continue; }
                    if (!InText(x)) break;
                    nonNull++;
                    i += 8;
                }
                runs.Add((start, (i - start) / 8, nonNull));
            }

            for (int k = 0; k < runs.Count; k++)
            {
                var (start, slots, nonNull) = runs[k];
                if (slots < 24) continue;

                var foreign = new List<(int, ulong)>();
                int end = start + slots * 8;
                int m = k;
                while (m + 1 < runs.Count)
                {
                    var next = runs[m + 1];
                    int gapBytes = next.Start - end;
                    if (gapBytes is <= 0 or > 8 * 8) break;
                    if (next.Slots < 24) break;
                    for (int q = 0; q < gapBytes; q += 8)
                    {
                        ulong fv = BitConverter.ToUInt64(buf, end + q);
                        foreign.Add(((end + q - start) / 8, fv));
                    }
                    slots += gapBytes / 8 + next.Slots;
                    nonNull += gapBytes / 8 + next.NonNull;
                    end = next.Start + next.Slots * 8;
                    m++;
                }

                if (slots >= 100 && nonNull >= 80)
                {
                    var tbl = new VmTable
                    {
                        Address = secVa + (ulong)start,
                        Slots = slots,
                        NonNull = nonNull,
                        OutsideJvm = foreign.Count,
                        Foreign = foreign,
                        Kind = L("pointer array", "array de punteros"),
                    };
                    AnchorInterface(buf, secVa, start, slots, tbl);
                    res.Add(tbl);
                }
                k = m;
            }
        }
        return res;
    }

    private const int JvmtiSlots = 156;
    private const int JniSlots = 233;

    private static void AnchorInterface(byte[] buf, ulong secVa, int runStart, int slots,
        VmTable tbl)
    {
        int lastNonNull = -1;
        for (int i = slots - 1; i >= 0; i--)
        {
            if (BitConverter.ToUInt64(buf, runStart + i * 8) != 0) { lastNonNull = i; break; }
        }
        if (lastNonNull < 0) return;

        bool Try(int size, int leadingNulls, string kind)
        {
            int startSlot = lastNonNull - (size - 1);
            if (startSlot < 0) return false;
            for (int i = 0; i < leadingNulls; i++)
                if (BitConverter.ToUInt64(buf, runStart + (startSlot + i) * 8) != 0) return false;
            if (BitConverter.ToUInt64(buf, runStart + (startSlot + leadingNulls) * 8) == 0)
                return false;

            tbl.Kind = kind;
            tbl.Address = secVa + (ulong)(runStart + startSlot * 8);
            tbl.Slots = size;
            return true;
        }

        if (Try(JvmtiSlots, 1, "jvmtiInterface_1_ (jvmtiEnv)")) return;
        Try(JniSlots, 4, "JNINativeInterface_ (JNIEnv)");
    }

    public static void Run(ScanContext ctx, SweepResult sweep, List<VmTable> tables)
    {
        var rep = ctx.Report;

        CheckCommandLineAndEnv(ctx, rep);
        CheckAgentModules(ctx, rep);
        CheckAgentExports(ctx, rep);
        CheckTellTaleThreads(ctx, rep);
        CheckVmTables(ctx, rep, tables);
        CheckAgentClasses(ctx, rep, sweep);

        rep.Section("JVM", RenderJvmSection(ctx, tables, sweep));
    }

    private static void CheckCommandLineAndEnv(ScanContext ctx, ScanReport rep)
    {
        string cmd = ctx.Target.GetCommandLine() ?? "";
        var env = ctx.Target.GetEnvironment();

        var agentFlags = new[] { "-javaagent:", "-agentpath:", "-agentlib:" };
        foreach (var flag in agentFlags)
        {
            int i = cmd.IndexOf(flag, StringComparison.OrdinalIgnoreCase);
            if (i < 0) continue;
            int end = cmd.IndexOf(' ', i);
            string val = end < 0 ? cmd.Substring(i) : cmd.Substring(i, end - i);
            rep.Report("JVM", L($"The JVM command line contains {flag}", $"La línea de comandos de la JVM contiene {flag}"), Severity.Critical,
                    L("An agent was attached at JVM startup. A clean Minecraft client must not have such arguments (except for debugging/profiling).", "Se conectó un agente al arrancar la JVM. Un cliente de Minecraft limpio no debe tener estos argumentos (salvo para depuración o perfilado)."))
                .Add(L("argument", "argumento"), val)
                .Add(L("full command line", "línea de comandos completa"), cmd);
        }

        foreach (var e in env)
        {
            string upper = e.ToUpperInvariant();
            bool interesting =
                upper.StartsWith("_JAVA_OPTIONS=") ||
                upper.StartsWith("JAVA_TOOL_OPTIONS=") ||
                upper.StartsWith("JDK_JAVA_OPTIONS=") ||
                upper.StartsWith("JAVA_OPTIONS=") ||
                upper.StartsWith("CLASSPATH=");
            if (!interesting) continue;

            int eq = e.IndexOf('=');
            string value = eq >= 0 ? e[(eq + 1)..].Trim() : "";
            bool hasAgent = agentFlags.Any(f => e.Contains(f, StringComparison.OrdinalIgnoreCase));
            rep.Report("JVM",
                    L($"Process environment variable: {e.Split('=')[0]}", $"Variable de entorno del proceso: {e.Split('=')[0]}") +
                    (value.Length == 0 ? L(" (empty)", " (vacía)") : ""),
                    hasAgent ? Severity.Critical
                        : value.Length == 0 ? Severity.Info : Severity.Medium,
                    L("_JAVA_OPTIONS / JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS let JVM arguments (including -javaagent) be added silently without editing the launcher. The Minecraft launcher usually clears these variables.", "_JAVA_OPTIONS / JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS permiten añadir en silencio argumentos de la JVM (incluido -javaagent) sin modificar el launcher. El launcher de Minecraft suele vaciar estas variables."))
                .Add(L("value", "valor"), e);
        }

        rep.Report("JVM", L("Process command line and environment", "Línea de comandos y entorno del proceso"), Severity.Info, null)
            .Add(L("command line", "línea de comandos"), cmd)
            .Add(L("working directory", "directorio de trabajo"), ctx.Target.GetCurrentDirectory() ?? "-")
            .Add("DllPath", ctx.Target.GetDllPath() ?? "-")
            .Block(L("Environment", "Entorno"), string.Join("\n", env.Select(x => "  " + x)));
    }

    private static void CheckAgentModules(ScanContext ctx, ScanReport rep)
    {
        foreach (var im in ctx.Images)
        {
            var hit = AgentModules.FirstOrDefault(
                m => im.Name.Equals(m, StringComparison.OrdinalIgnoreCase));
            if (hit is null) continue;

            Severity sev = hit switch
            {
                "instrument.dll" => Severity.Critical,
                "jdwp.dll" => Severity.Critical,
                "attach.dll" => Severity.High,
                _ => Severity.Info,
            };
            string why = hit switch
            {
                "instrument.dll" =>
                    L("instrument.dll is the native part of java.lang.instrument. It is loaded into the JVM ONLY when a Java agent is attached: either -javaagent at startup or dynamically through the Attach API. A normal Minecraft does not load it.", "instrument.dll es la parte nativa de java.lang.instrument. Se carga en la JVM SOLO al conectar un agente Java: con -javaagent al arrancar o dinámicamente mediante la Attach API. Un Minecraft normal no la carga."),
                "jdwp.dll" =>
                    L("jdwp.dll is the Java debugger transport. Its presence means the JVM was started with a debug agent or a debugger attached to it.", "jdwp.dll es el transporte del depurador de Java. Su presencia significa que la JVM se inició con un agente de depuración o que un depurador se conectó a ella."),
                "attach.dll" =>
                    L("attach.dll is used by the Dynamic Attach mechanism.", "attach.dll la usa el mecanismo Dynamic Attach."),
                _ => L("A JVM service infrastructure module; not evidence on its own, but important together with other signs.", "Módulo de la infraestructura de servicio de la JVM; no es una prueba por sí solo, pero es importante junto con otros indicios."),
            };

            var f = rep.Report("JVM", L($"Module loaded: {im.Name}", $"Módulo cargado: {im.Name}"), sev, why);
            ModuleAnalyzer.FillModuleData(ctx, f, im);
        }
    }

    private static void CheckAgentExports(ScanContext ctx, ScanReport rep)
    {
        string[] entries = { "Agent_OnLoad", "Agent_OnAttach", "Agent_OnUnload",
                             "Agent_OnLoad_L", "Agent_OnAttach_L", "JVM_OnLoad" };

        foreach (var im in ctx.Images)
        {
            if (!im.Pe.Valid) continue;
            if (im.Name.Equals("instrument.dll", StringComparison.OrdinalIgnoreCase)) continue;

            var found = im.Pe.Exports.Entries
                .Where(e => entries.Any(x => e.Name.StartsWith(x, StringComparison.Ordinal)))
                .Select(e => e.Name)
                .Distinct()
                .ToList();
            if (found.Count == 0) continue;

            var f = rep.Report("JVM",
                L($"Module {im.Name} exports JVMTI agent entry points: ", $"El módulo {im.Name} exporta puntos de entrada de un agente JVMTI: ") +
                string.Join(", ", found),
                Severity.Critical,
                L("A native JVMTI agent must export Agent_OnLoad (loading at startup) or Agent_OnAttach (attaching to a live JVM). No library of a normal Minecraft exports these functions. The presence of such a module in the process means a native agent attached to the JVM — this is exactly the mechanism of JVMTI cheats.", "Un agente JVMTI nativo debe exportar Agent_OnLoad (carga al arrancar) o Agent_OnAttach (conexión a una JVM en ejecución). Ninguna biblioteca de un Minecraft normal exporta estas funciones. La presencia de un módulo así en el proceso significa que un agente nativo se conectó a la JVM: es justamente el mecanismo de los cheats JVMTI."));
            ModuleAnalyzer.FillModuleData(ctx, f, im);
        }
    }

    private static readonly (string Prefix, Severity Sev, string Why)[] AgentClasses =
    {
        ("sun/instrument/InstrumentationImpl", Severity.Critical,
            L("Implementation of java.lang.instrument.Instrumentation. This class is loaded into the JVM only when a Java agent is attached (-javaagent or dynamic attach). A clean Minecraft does not have it.", "Implementación de java.lang.instrument.Instrumentation. Esta clase se carga en la JVM únicamente al conectar un agente Java (-javaagent o attach dinámico). Un Minecraft limpio no la tiene.")),
        ("java/lang/instrument/ClassFileTransformer", Severity.Critical,
            L("The interface for transforming the bytecode of loaded classes — what Java cheats use to patch game code on the fly. Loaded only together with an agent.", "La interfaz para transformar el bytecode de las clases cargadas: lo que usan los cheats de Java para parchear el código del juego en caliente. Solo se carga junto con un agente.")),
        ("java/lang/instrument/Instrumentation", Severity.Critical,
            L("Instrumentation API. Present only when an agent is attached.", "API de instrumentación. Solo está presente con un agente conectado.")),
        ("sun/tools/attach/", Severity.Critical,
            L("Attach API classes inside the game itself mean the process attached an agent to itself (self-attach) — a typical way to inject a Java cheat without an external file.", "Las clases de la Attach API dentro del propio juego significan que el proceso se conectó un agente a sí mismo (self-attach): una forma típica de inyectar un cheat de Java sin un archivo externo.")),
        ("com/sun/tools/attach/VirtualMachine", Severity.Critical,
            L("Attach API loaded inside the game process.", "Attach API cargada dentro del proceso del juego.")),
        ("jdk/internal/agent/", Severity.Medium,
            L("JVM management agent infrastructure.", "Infraestructura del agente de gestión de la JVM.")),
        ("org/objectweb/asm/ClassWriter", Severity.Info,
            L("ASM is used by Fabric itself — not evidence on its own.", "ASM lo usa el propio Fabric: no es una prueba por sí solo.")),
    };

    private static void CheckAgentClasses(ScanContext ctx, ScanReport rep, SweepResult sweep)
    {
        if (sweep.Classes.Count == 0) return;

        foreach (var (prefix, sev, why) in AgentClasses)
        {
            if (sev == Severity.Info) continue;
            var hits = sweep.Classes.Values
                .Where(c => c.Name.StartsWith(prefix, StringComparison.Ordinal))
                .ToList();
            if (hits.Count == 0) continue;

            var f = rep.Report("JVM",
                L($"Bytecode of «{prefix}*» classes found in memory ({hits.Count})", $"Se encontró en memoria bytecode de clases «{prefix}*» ({hits.Count})"), sev, why);
            foreach (var c in hits.Take(20))
                f.Add(c.Name, L($"0x{c.Address:X}, class version {c.MajorVersion}", $"0x{c.Address:X}, versión de clase {c.MajorVersion}") +
                              (c.SuperName.Length > 0 ? $", extends {c.SuperName}" : ""));
        }
    }

    private static void CheckTellTaleThreads(ScanContext ctx, ScanReport rep)
    {
        foreach (var th in ctx.Threads)
        {
            if (th.Description is null) continue;
            foreach (var (name, sev0, why) in TellTaleThreads)
            {
                if (!th.Description.Contains(name, StringComparison.OrdinalIgnoreCase)) continue;

                var sev = sev0;
                if (name == "Attach Listener" && ctx.Target.StartTimeUtc != default &&
                    th.CreateTimeUtc != default &&
                    (th.CreateTimeUtc - ctx.Target.StartTimeUtc).TotalSeconds > 10)
                    sev = Severity.High;

                var f = rep.Report("JVM",
                    L($"JVM thread «{th.Description}» is present in the process", $"El proceso tiene el hilo de la JVM «{th.Description}»"), sev, why);
                f.Add("TID", th.Tid.ToString());
                if (th.CreateTimeUtc != default)
                {
                    f.Add(L("created", "creado"), th.CreateTimeUtc.ToLocalTime().ToString("O"));
                    if (ctx.Target.StartTimeUtc != default)
                        f.Add(L("created after", "creado tras"),
                            L($"{(th.CreateTimeUtc - ctx.Target.StartTimeUtc).TotalSeconds:F2} s after JVM start", $"{(th.CreateTimeUtc - ctx.Target.StartTimeUtc).TotalSeconds:F2} s desde el inicio de la JVM"));
                }
                ulong a = th.Win32StartAddress != 0 ? th.Win32StartAddress : th.KernelStartAddress;
                f.Add(L("start address", "dirección de inicio"), ctx.Describe(a));
            }
        }
    }

    private static void CheckVmTables(ScanContext ctx, ScanReport rep, List<VmTable> tables)
    {
        var referenced = tables.Where(t => (t.RefPattern?.TotalHits ?? 0) > 0).ToList();
        if (tables.Count > 0 && tables.All(t => t.RefPattern is null))
        {
            rep.Report("JVM", L("The search for jvmtiEnv objects was not performed", "No se buscaron objetos jvmtiEnv"), Severity.Info,
                L("Counting references to JNI/JVMTI tables requires the full memory scan. It is disabled by --no-strings / --fast.", "Contar las referencias a las tablas JNI/JVMTI requiere el escaneo completo de memoria. Está desactivado con --no-strings / --fast."));
            return;
        }

        foreach (var tbl in referenced)
        {
            var rp = tbl.RefPattern!;
            bool isJni = tbl.Kind.StartsWith("JNINativeInterface");
            bool isJvmti = tbl.Kind.StartsWith("jvmtiInterface");
            if (!isJni && !isJvmti) continue;

            if (isJni)
            {
                var fi = rep.Report("JVM",
                    L($"JNI table found: 0x{tbl.Address:X}, references from memory: {rp.TotalHits}", $"Tabla JNI encontrada: 0x{tbl.Address:X}, referencias desde la memoria: {rp.TotalHits}"),
                    Severity.Info,
                    L("This is the normal JNINativeInterface_ table and the JNIEnv pointers of Java threads. The number of references roughly equals the number of Java threads.", "Es la tabla normal JNINativeInterface_ y los punteros JNIEnv de los hilos Java. El número de referencias es aproximadamente igual al número de hilos Java."));
                fi.Add(L("slots", "entradas"), tbl.Slots.ToString());
                fi.Add(L("non-empty slots", "entradas no vacías"), tbl.NonNull.ToString());
                ReportForeignSlots(ctx, rep, tbl, "JNI");
                continue;
            }

            {
                var f = rep.Report("JVM",
                    L($"Found {rp.TotalHits} references to the jvmtiInterface_1_ table at 0x{tbl.Address:X} — these are jvmtiEnv objects", $"Se encontraron {rp.TotalHits} referencias a la tabla jvmtiInterface_1_ en 0x{tbl.Address:X}: son objetos jvmtiEnv"),
                    Severity.Critical,
                    L("Every agent attached to the JVM receives a jvmtiEnv object whose first field is a pointer to the jvmtiInterface_1_ table in jvm.dll. A Minecraft process without agents has none of these objects. After DisposeEnvironment the object memory is freed, but its content usually stays until reused — so the trace survives unloading the cheat.", "Cada agente conectado a la JVM recibe un objeto jvmtiEnv cuyo primer campo es un puntero a la tabla jvmtiInterface_1_ de jvm.dll. Un proceso de Minecraft sin agentes no tiene ninguno de estos objetos. Tras DisposeEnvironment la memoria del objeto se libera, pero su contenido suele permanecer hasta que se reutiliza: el rastro sobrevive a la descarga del cheat."));
                f.Add(L("table address", "dirección de la tabla"), tbl.Address);
                f.Add(L("slots in the table", "entradas en la tabla"), tbl.Slots.ToString());
                f.Add(L("non-empty slots", "entradas no vacías"), tbl.NonNull.ToString());

                var sb = new StringBuilder();
                foreach (var (addr, region) in rp.Hits.Take(64))
                {
                    sb.AppendLine(L($"  0x{addr:X}  in {region.TypeString}/{region.ProtectString} (allocation 0x{region.AllocationBase:X})", $"  0x{addr:X}  en {region.TypeString}/{region.ProtectString} (asignación 0x{region.AllocationBase:X})"));
                    var head = ctx.Target.ReadBytes(addr, 64);
                    if (head is not null)
                        sb.AppendLine(HexDump.Format(head, addr).Replace("\n", "\n    "));
                }
                f.Block(L("Objects found", "Objetos encontrados"), sb.ToString().TrimEnd());
                ReportForeignSlots(ctx, rep, tbl, "JVMTI");
            }
        }

        var jvmti = tables.FirstOrDefault(t => t.Kind.StartsWith("jvmtiInterface"));
        if (jvmti is not null && (jvmti.RefPattern?.TotalHits ?? 0) == 0)
        {
            rep.Report("JVM",
                    L("No jvmtiEnv objects found in memory — no traces of a JVMTI agent", "No se encontraron objetos jvmtiEnv en memoria: no hay rastros de un agente JVMTI"),
                    Severity.Info,
                    L("The jvmtiInterface_1_ table was found in jvm.dll, but no object in memory refers to it. So no JVMTI environment was created during the lifetime of the process — or its memory has already been completely overwritten.", "Se encontró la tabla jvmtiInterface_1_ en jvm.dll, pero ningún objeto en memoria la referencia. Por tanto, no se creó ningún entorno JVMTI durante la vida del proceso, o su memoria ya se sobrescribió por completo."))
                .Add(L("table address", "dirección de la tabla"), jvmti.Address)
                .Add(L("slots", "entradas"), jvmti.Slots.ToString());
        }

    }

    private static void ReportForeignSlots(ScanContext ctx, ScanReport rep, VmTable tbl,
        string kind, Severity sev = Severity.Critical)
    {
        if (tbl.OutsideJvm == 0) return;
        var f = rep.Report("JVM",
            L($"Table {kind} at 0x{tbl.Address:X}: {tbl.OutsideJvm} slots point outside jvm.dll", $"Tabla {kind} en 0x{tbl.Address:X}: {tbl.OutsideJvm} entradas apuntan fuera de jvm.dll"),
            sev,
            L("A JNI/JVMTI function table consists of pointers into the code of jvm.dll itself. A slot pointing outside means the corresponding function is hooked.", "Una tabla de funciones JNI/JVMTI está formada por punteros al código de la propia jvm.dll. Una entrada que apunta fuera significa que la función correspondiente está interceptada."));
        foreach (var (slot, target) in tbl.Foreign.Take(64))
            f.Add(L($"slot #{slot}", $"entrada n.º {slot}"), $"0x{target:X} → {ctx.Describe(target)}");
    }

    private static readonly string[] ExpectedRoots =
    {
        "java/", "javax/", "jdk/", "sun/", "com/sun/", "net/minecraft/", "com/mojang/",
        "net/fabricmc/", "org/objectweb/asm/", "org/spongepowered/", "org/slf4j/",
        "org/apache/", "com/google/", "io/netty/", "it/unimi/", "org/lwjgl/", "org/joml/",
        "com/ibm/icu/", "oshi/", "com/fasterxml/", "org/lz4/", "net/java/dev/jna/",
        "com/jcraft/", "org/jcraft/", "com/nimbusds/", "net/minidev/", "joptsimple/",
        "org/quiltmc/", "com/mojang/blaze3d/", "net/minecraftforge/", "cpw/mods/",
        "org/lwjglx/", "com/electronwill/", "org/objenesis/", "me/", "dev/", "mixin/",
        "org/intellij/", "org/jetbrains/", "com/electron", "org/w3c/", "org/xml/",
        "javassist/", "kotlin/", "kotlinx/", "org/checkerframework/", "com/mojang/logging/",
    };

    private static string RenderJvmSection(ScanContext ctx, List<VmTable> tables, SweepResult sweep)
    {
        var sb = new StringBuilder();
        var jvm = FindJvm(ctx);
        sb.AppendLine(jvm is null
            ? L("jvm.dll not found — the process is not a JVM or the module is hidden.", "no se encontró jvm.dll: el proceso no es una JVM o el módulo está oculto.")
            : L($"jvm.dll: base 0x{jvm.Base:X}, size 0x{jvm.Size:X}, path {jvm.Path}", $"jvm.dll: base 0x{jvm.Base:X}, tamaño 0x{jvm.Size:X}, ruta {jvm.Path}"));
        sb.AppendLine();
        sb.AppendLine(L($"VM function table candidates: {tables.Count} (with references from memory: {tables.Count(x => (x.RefPattern?.TotalHits ?? 0) > 0)})", $"Candidatas a tablas de funciones de la VM: {tables.Count} (con referencias desde la memoria: {tables.Count(x => (x.RefPattern?.TotalHits ?? 0) > 0)})"));
        foreach (var t in tables.Where(x => (x.RefPattern?.TotalHits ?? 0) > 0 || x.Slots >= 150)
                                .OrderByDescending(x => x.RefPattern?.TotalHits ?? 0).Take(40))
            sb.AppendLine(L($"  0x{t.Address:X}  slots={t.Slots,4}  non-empty={t.NonNull,4}  foreign={t.OutsideJvm}  refs in memory={t.RefPattern?.TotalHits ?? -1}  {t.Kind}", $"  0x{t.Address:X}  entradas={t.Slots,4}  no vacías={t.NonNull,4}  ajenas={t.OutsideJvm}  refs en memoria={t.RefPattern?.TotalHits ?? -1}  {t.Kind}"));
        sb.AppendLine();
        sb.AppendLine(L("JVM threads (by name):", "Hilos de la JVM (por nombre):"));
        foreach (var th in ctx.Threads.Where(x => x.Description is not null)
                                      .OrderBy(x => x.CreateTimeUtc))
        {
            string dt = ctx.Target.StartTimeUtc != default && th.CreateTimeUtc != default
                ? L($"+{(th.CreateTimeUtc - ctx.Target.StartTimeUtc).TotalSeconds,8:F1}s", $"+{(th.CreateTimeUtc - ctx.Target.StartTimeUtc).TotalSeconds,8:F1}s") : "";
            sb.AppendLine($"  {th.Tid,-8} {dt,-12} {th.Description}");
        }
        sb.AppendLine();
        sb.AppendLine(L($"Class files in memory: {sweep.Classes.Count}", $"Archivos de clase en memoria: {sweep.Classes.Count}"));
        return sb.ToString();
    }
}
