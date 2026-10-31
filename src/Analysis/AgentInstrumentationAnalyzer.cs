using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class AgentInstrumentationAnalyzer
{
    private const string Impl = "sun/instrument/InstrumentationImpl";
    private const string TransformerIface = "java/lang/instrument/ClassFileTransformer";

    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        sb.AppendLine(L("JAVA AGENT MECHANISM: INSTRUMENTATION OBJECT AND CLASS TRANSFORMERS", "MECANISMO DE AGENTES JAVA: OBJETO INSTRUMENTATION Y TRANSFORMADORES DE CLASES"));
        sb.AppendLine();

        var m = ctx.Java;
        var idx = ctx.HeapIndex;
        if (m is null)
        {
            sb.AppendLine(L("  class map unavailable — check skipped.", "  mapa de clases no disponible: comprobación omitida."));
            ctx.Report.Section(L("JAVA AGENT MECHANISM", "MECANISMO DE AGENTES JAVA"), sb.ToString());
            return;
        }

        ClassPresence(ctx, m, sb);

        if (idx is null || !idx.Valid)
        {
            sb.AppendLine(L("  Java heap index not built — objects were not searched.", "  índice del heap de Java no construido: no se buscaron objetos."));
            ctx.Report.Section(L("JAVA AGENT MECHANISM", "MECANISMO DE AGENTES JAVA"), sb.ToString());
            return;
        }

        Instances(ctx, m, idx, sb);
        Transformers(ctx, m, idx, sb);

        ctx.Report.Section(L("JAVA AGENT MECHANISM", "MECANISMO DE AGENTES JAVA"), sb.ToString());
    }

    private static void ClassPresence(ScanContext ctx, JavaMeta m, StringBuilder sb)
    {
        string[] marks =
        {
            Impl, "sun/instrument/TransformerManager",
            "sun/instrument/TransformerManager$TransformerInfo",
            "java/lang/instrument/Instrumentation", TransformerIface,
            "java/lang/instrument/ClassDefinition",
            "java/lang/instrument/UnmodifiableClassException",
            "jdk/internal/module/Modules",
        };

        sb.AppendLine(L("LOADED CLASSES OF THE AGENT MECHANISM", "CLASES CARGADAS DEL MECANISMO DE AGENTES"));
        var loaded = new List<string>();
        foreach (string s in marks)
        {
            ulong k = m.KlassByName(s);
            sb.AppendLine(L($"  {(k != 0 ? "YES   " : "no    ")} {s}", $"  {(k != 0 ? "SÍ    " : "no    ")} {s}") +
                          (k != 0 ? $"   Klass 0x{k:X}" : ""));
            if (k != 0) loaded.Add(s);
        }
        sb.AppendLine();

        var strong = loaded.Where(s => s.StartsWith("sun/instrument/", StringComparison.Ordinal) ||
                                       s == TransformerIface ||
                                       s == "java/lang/instrument/ClassDefinition").ToList();
        if (strong.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            L($"Java agent mechanism classes are loaded in memory ({strong.Count} of {marks.Length} searched)", $"Hay clases del mecanismo de agentes Java cargadas en memoria ({strong.Count} de {marks.Length} buscadas)"),
            Severity.High,
            L("The runtime loads agent mechanism classes lazily — only when an agent is actually attached, at startup with -javaagent or on the fly through attach. A Fabric Minecraft client has no agents: the mod loader rewrites bytecode with its own class loader and does not use the agent mechanism. So the mere fact that these classes are loaded means the agent mechanism was deployed in this process. The class stays loaded forever — detaching the agent does not unload it.", "El entorno de ejecución carga las clases del mecanismo de agentes de forma perezosa: solo cuando realmente se conecta un agente, al arrancar con -javaagent o en caliente mediante attach. Un cliente de Minecraft con Fabric no tiene agentes: el cargador de mods reescribe el bytecode con su propio cargador de clases y no usa el mecanismo de agentes. Por eso el simple hecho de que estas clases estén cargadas significa que el mecanismo de agentes se desplegó en este proceso. La clase queda cargada para siempre: desconectar el agente no la descarga."));
        foreach (string s in loaded) f.Add(L("loaded", "cargada"), s);
    }

    private static void Instances(ScanContext ctx, JavaMeta m, JavaHeapIndex idx, StringBuilder sb)
    {
        sb.AppendLine(L("INSTRUMENTATION OBJECTS", "OBJETOS INSTRUMENTATION"));

        ulong implKlass = m.KlassByName(Impl);
        if (implKlass == 0)
        {
            sb.AppendLine(L("  implementation class not loaded — there can be no objects.", "  clase de implementación no cargada: no puede haber objetos."));
            sb.AppendLine();
            return;
        }

        var live = idx.LiveInstancesOf(Impl);
        var dead = DeadInstancesOf(idx, implKlass);
        sb.AppendLine(L($"  live objects: {live.Count}, in the dead zone: {dead.Count}", $"  objetos vivos: {live.Count}, en la zona muerta: {dead.Count}"));

        var all = live.Select(o => (Obj: o, Dead: false))
            .Concat(dead.Select(o => (Obj: o, Dead: true))).ToList();
        if (all.Count == 0)
        {
            sb.AppendLine();
            return;
        }

        var rows = new List<(ulong Obj, bool Dead, long Native, string Caps, List<string> Ts)>();
        foreach (var (obj, isDead) in all)
        {
            long native = m.LongField(obj, "mNativeAgent");
            var caps = new List<string>();
            foreach (string cap in new[]
                     {
                         "mEnvironmentSupportsRedefineClasses",
                         "mEnvironmentSupportsRetransformClassesKnown",
                         "mEnvironmentSupportsRetransformClasses",
                         "mEnvironmentSupportsNativeMethodPrefix",
                     })
            {
                int off = m.FieldOffset(m.KlassOf(obj), cap);
                if (off < 0) continue;
                caps.Add(L($"{cap}={(ctx.Target.ReadU8(obj + (ulong)off) != 0 ? "yes" : "no")}", $"{cap}={(ctx.Target.ReadU8(obj + (ulong)off) != 0 ? "sí" : "no")}"));
            }

            var ts = new List<string>();
            foreach (string mgr in new[] { "mTransformerManager", "mRetransfomableTransformerManager",
                         "mRetransformableTransformerManager" })
            {
                ulong tm = m.OopField(obj, mgr);
                if (tm == 0) continue;
                foreach (string t in ReadTransformerManager(m, tm))
                    ts.Add($"{mgr}: {t}");
            }

            rows.Add((obj, isDead, native, string.Join(", ", caps), ts));
        }

        foreach (var r in rows)
        {
            sb.AppendLine(L($"  object 0x{r.Obj:X}{(r.Dead ? " [in the dead zone]" : "")}", $"  objeto 0x{r.Obj:X}{(r.Dead ? " [en la zona muerta]" : "")}"));
            sb.AppendLine(L($"      native agent part: 0x{r.Native:X} ({DescribeNative(ctx, (ulong)r.Native)})", $"      parte nativa del agente: 0x{r.Native:X} ({DescribeNative(ctx, (ulong)r.Native)})"));
            sb.AppendLine(L($"      capabilities: {(r.Caps.Length > 0 ? r.Caps : "not read")}", $"      capacidades: {(r.Caps.Length > 0 ? r.Caps : "no leídas")}"));
            foreach (string t in r.Ts) sb.AppendLine(L($"      transformer — {t}", $"      transformador: {t}"));
            if (r.Ts.Count == 0) sb.AppendLine(L("      transformer lists are empty", "      las listas de transformadores están vacías"));
        }
        sb.AppendLine();

        var f = ctx.Report.Report("JVM",
            L($"{rows.Count} Instrumentation objects found in the Java heap (in the dead zone: {rows.Count(r => r.Dead)})", $"Se encontraron {rows.Count} objetos Instrumentation en el heap de Java (en la zona muerta: {rows.Count(r => r.Dead)})"),
            Severity.Critical,
            L("The runtime creates an Instrumentation object exactly once per agent and hands it to the premain or agentmain method. Its existence means a Java agent was present in this process. A clean Minecraft client has no Instrumentation objects at all: the mod loader works with its own class loader and does not use the agent mechanism. An object found in the dead zone of the heap means the agent finished and was detached, and its object has already been collected by the garbage collector — but its content can still be read.", "El entorno de ejecución crea un objeto Instrumentation exactamente una vez por agente y se lo entrega al método premain o agentmain. Su existencia significa que en este proceso hubo un agente Java. Un cliente de Minecraft limpio no tiene ningún objeto Instrumentation: el cargador de mods trabaja con su propio cargador de clases y no usa el mecanismo de agentes. Un objeto encontrado en la zona muerta del heap significa que el agente terminó y se desconectó, y su objeto ya fue recogido por el recolector de basura, pero su contenido aún se puede leer."));
        foreach (var r in rows)
        {
            f.Add(L($"object 0x{r.Obj:X}", $"objeto 0x{r.Obj:X}"),
                L($"{(r.Dead ? "in the dead zone, " : "")}native part 0x{r.Native:X} ({DescribeNative(ctx, (ulong)r.Native)}), capabilities: {r.Caps}", $"{(r.Dead ? "en la zona muerta, " : "")}parte nativa 0x{r.Native:X} ({DescribeNative(ctx, (ulong)r.Native)}), capacidades: {r.Caps}"));
            foreach (string t in r.Ts.Take(20)) f.Add(L("    transformer", "    transformador"), t);
        }
    }

    private static string DescribeNative(ScanContext ctx, ulong addr)
    {
        if (addr == 0) return L("no native part", "sin parte nativa");
        var r = ctx.RegionAt(addr);
        if (r is null) return L("MEMORY AT THIS ADDRESS IS NOT MAPPED — the native part is gone", "LA MEMORIA EN ESTA DIRECCIÓN NO ESTÁ PROYECTADA: la parte nativa desapareció");
        return L($"{r.TypeString}/{r.ProtectString}, allocation base 0x{r.AllocationBase:X}", $"{r.TypeString}/{r.ProtectString}, base de la asignación 0x{r.AllocationBase:X}");
    }

    private static List<string> ReadTransformerManager(JavaMeta m, ulong tm)
    {
        var res = new List<string>();
        ulong arr = m.OopField(tm, "mTransformerList");
        if (arr == 0) arr = m.OopField(tm, "transformerList");
        if (arr == 0) return res;

        foreach (ulong info in m.ObjArray(arr, 4096))
        {
            if (info == 0) continue;
            ulong t = m.OopField(info, "mTransformer");
            if (t == 0) t = m.OopField(info, "transformer");
            string cls = t != 0 ? m.ClassNameOf(t) ?? "?" : m.ClassNameOf(info) ?? "?";
            res.Add(L($"{cls} (object 0x{(t != 0 ? t : info):X})", $"{cls} (objeto 0x{(t != 0 ? t : info):X})"));
        }
        return res;
    }

    private static void Transformers(ScanContext ctx, JavaMeta m, JavaHeapIndex idx,
        StringBuilder sb)
    {
        sb.AppendLine(L("BYTECODE TRANSFORMER OBJECTS IN THE HEAP", "OBJETOS TRANSFORMADORES DE BYTECODE EN EL HEAP"));

        if (m.KlassByName(TransformerIface) == 0)
        {
            sb.AppendLine(L("  transformer interface not loaded — nothing to search for.", "  interfaz de transformador no cargada: no hay nada que buscar."));
            sb.AppendLine();
            return;
        }

        var rows = new List<(string Klass, long Live, long Dead, ulong Sample)>();
        foreach (var st in idx.Stats.Values)
        {
            if (st.Klass == 0 || st.Name.Length == 0) continue;
            if (!m.IsAssignableTo(st.Klass, TransformerIface)) continue;
            ulong sample = st.LiveSamples.FirstOrDefault();
            if (sample == 0) sample = st.DeadSamples.FirstOrDefault();
            rows.Add((st.Name, st.Live, st.Dead, sample));
        }

        sb.AppendLine(L($"  distinct transformer classes: {rows.Count}", $"  clases transformadoras distintas: {rows.Count}"));
        foreach (var r in rows.OrderByDescending(x => x.Live + x.Dead))
            sb.AppendLine(L($"      {r.Klass}   live {r.Live}, in the dead zone {r.Dead}", $"      {r.Klass}   vivos {r.Live}, en la zona muerta {r.Dead}") +
                          (r.Sample != 0 ? L($", sample 0x{r.Sample:X}", $", ejemplo 0x{r.Sample:X}") : ""));
        sb.AppendLine();
        if (rows.Count == 0) return;

        var jars = ctx.Jars;
        var f = ctx.Report.Report("JAVA",
            L($"The heap contains objects of {rows.Count} classes that rewrite the bytecode of other classes", $"El heap contiene objetos de {rows.Count} clases que reescriben el bytecode de otras clases"),
            Severity.Critical,
            L("A class implementing the transformer interface receives the bytecode of EVERY loaded class and returns it modified. This is exactly the mechanism for rewriting the game on the fly. Such a class can be registered only through the Instrumentation object, i.e. only as an agent. It can be removed from the registration list, but not from the heap: the object stays until garbage collection, and after collection its content can still be read in the dead zone for some time.", "Una clase que implementa la interfaz de transformador recibe el bytecode de CADA clase que se carga y lo devuelve modificado. Es justamente el mecanismo para reescribir el juego en caliente. Una clase así solo puede registrarse a través del objeto Instrumentation, es decir, solo siendo un agente. Puede quitarse de la lista de registros, pero no del heap: el objeto permanece hasta la recolección de basura y, después, su contenido aún se puede leer durante un tiempo en la zona muerta."));
        foreach (var r in rows.OrderByDescending(x => x.Live + x.Dead).Take(50))
        {
            string origin = jars is null ? L("archive index not built", "índice de archivos no construido")
                : NoOriginOnDisk(ctx, r.Klass) ? L("NOT IN ARCHIVES", "NO ESTÁ EN LOS ARCHIVOS")
                : JarIndex.IsRuntimeClass(r.Klass) ? L("runtime class", "clase del entorno de ejecución")
                : jars.Contains(r.Klass) ? L("present in archives", "presente en los archivos")
                : L("origin not established", "origen no establecido");
            f.Add(r.Klass, L($"live {r.Live}, in the dead zone {r.Dead} [{origin}]", $"vivos {r.Live}, en la zona muerta {r.Dead} [{origin}]"));
        }
    }

    private static bool NoOriginOnDisk(ScanContext ctx, string name)
    {
        if (name.Length == 0) return false;
        var jars = ctx.Jars;
        if (jars is null) return false;
        if (JarIndex.IsRuntimeClass(name)) return false;
        if (JarIndex.GeneratedKind(name) is not null) return false;
        if (ctx.GameIsRemapped && AgentInfra.IsVanillaObf(name)) return true;
        return !jars.Contains(name) && jars.OwningPackage(name) is null;
    }

    private static List<ulong> DeadInstancesOf(JavaHeapIndex idx, ulong klass) =>
        idx.Stats.TryGetValue(klass, out var st) ? st.DeadSamples : new List<ulong>();
}
