using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class BootLoaderIntrusionAnalyzer
{
    private sealed class Cld
    {
        public ulong Address;
        public ulong LoaderOop;
        public string LoaderClass = "";
        public bool HasMirrorHolder;
        public readonly List<(ulong Klass, string Name)> Klasses = new();
    }

    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        sb.AppendLine(L("CLASSES IN PRIVILEGED LOADERS", "CLASES EN CARGADORES PRIVILEGIADOS"));
        sb.AppendLine();

        var vm = ctx.Vm;
        var m = ctx.Java;
        if (vm is null || !vm.Valid || m is null)
        {
            sb.AppendLine(L("  HotSpot structure layout or class map unavailable — check skipped.", "  disposición de estructuras HotSpot o mapa de clases no disponibles: comprobación omitida."));
            ctx.Report.Section(L("PRIVILEGED LOADERS", "CARGADORES PRIVILEGIADOS"), sb.ToString());
            return;
        }

        int offLoader = vm.Off("ClassLoaderData", "_class_loader");
        int offKlasses = vm.Off("ClassLoaderData", "_klasses");
        int offNextK = vm.Off("Klass", "_next_link");
        int offMirrorHolder = vm.OffAny("ClassLoaderData",
            "_has_class_mirror_holder", "_is_unsafe_anonymous");

        sb.AppendLine($"  ClassLoaderData::_class_loader = {offLoader}, _klasses = {offKlasses}");
        sb.AppendLine(L($"  Klass::_next_link = {offNextK}, hidden flag = {offMirrorHolder}", $"  Klass::_next_link = {offNextK}, indicador de oculta = {offMirrorHolder}"));
        sb.AppendLine(L($"  loader objects in the graph: {ctx.ClassLoaderDatas.Count}", $"  objetos cargadores en el grafo: {ctx.ClassLoaderDatas.Count}"));
        sb.AppendLine();

        if (offLoader < 0 || offKlasses < 0 || offNextK < 0 || ctx.ClassLoaderDatas.Count == 0)
        {
            sb.AppendLine(L("  loader graph not parsed — check skipped.", "  grafo de cargadores no analizado: comprobación omitida."));
            ctx.Report.Section(L("PRIVILEGED LOADERS", "CARGADORES PRIVILEGIADOS"), sb.ToString());
            return;
        }

        var c = m.Cache;
        var clds = new List<Cld>();

        foreach (ulong cldAddr in ctx.ClassLoaderDatas)
        {
            var cld = new Cld { Address = cldAddr };
            ulong handle = c.U64(cldAddr + (ulong)offLoader);
            cld.LoaderOop = handle == 0 ? 0 : c.U64(handle);
            cld.LoaderClass = cld.LoaderOop == 0
                ? L("<bootstrap loader>", "<cargador de arranque>")
                : m.ClassNameOf(cld.LoaderOop) ?? L("<undetermined>", "<no determinado>");
            if (offMirrorHolder >= 0)
                cld.HasMirrorHolder = ctx.Target.ReadU8(cldAddr + (ulong)offMirrorHolder) != 0;

            ulong k = c.U64(cldAddr + (ulong)offKlasses);
            int guard = 0;
            var seen = new HashSet<ulong>();
            while (k is >= 0x10000 and <= 0x7FFFFFFFFFFFFF && guard++ < 200_000)
            {
                if (!seen.Add(k)) break;
                string? n = m.KlassName(k);
                if (n is not null) cld.Klasses.Add((k, n));
                k = c.U64(k + (ulong)offNextK);
            }
            clds.Add(cld);
        }

        Render(clds, sb);
        ReportDuplicateBootLoaders(ctx, clds, sb);
        ReportIntruders(ctx, clds, sb);
        ReportHiddenClassLoaders(ctx, clds, sb);

        ctx.Report.Section(L("PRIVILEGED LOADERS", "CARGADORES PRIVILEGIADOS"), sb.ToString());
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

    private static bool Privileged(Cld cld) =>
        cld.LoaderOop == 0 ||
        cld.LoaderClass.EndsWith("$PlatformClassLoader", StringComparison.Ordinal) ||
        cld.LoaderClass.EndsWith("BootClassLoader", StringComparison.Ordinal);

    private static void Render(List<Cld> clds, StringBuilder sb)
    {
        sb.AppendLine(L("LOADERS AND THE NUMBER OF CLASSES IN EACH", "CARGADORES Y NÚMERO DE CLASES EN CADA UNO"));
        foreach (var cld in clds.OrderByDescending(x => x.Klasses.Count))
            sb.AppendLine(L($"  0x{cld.Address:X}  {cld.LoaderClass,-64} classes {cld.Klasses.Count}", $"  0x{cld.Address:X}  {cld.LoaderClass,-64} clases {cld.Klasses.Count}") +
                          (cld.HasMirrorHolder ? L("  [hidden class loader]", "  [cargador de clase oculta]") : "") +
                          (Privileged(cld) ? L("  [privileged]", "  [privilegiado]") : ""));
        sb.AppendLine();
    }

    private static void ReportDuplicateBootLoaders(ScanContext ctx, List<Cld> clds,
        StringBuilder sb)
    {
        var nulls = clds.Where(x => x.LoaderOop == 0 && !x.HasMirrorHolder).ToList();
        sb.AppendLine(L($"LOADER OBJECTS WITH AN EMPTY LOADER REFERENCE: {nulls.Count}", $"OBJETOS CARGADORES CON REFERENCIA VACÍA AL CARGADOR: {nulls.Count}"));
        foreach (var cld in nulls)
            sb.AppendLine(L($"  0x{cld.Address:X}  classes {cld.Klasses.Count}", $"  0x{cld.Address:X}  clases {cld.Klasses.Count}"));
        sb.AppendLine();
        if (nulls.Count <= 1) return;

        var f = ctx.Report.Report("JVM",
            L($"The graph has {nulls.Count} loader objects with an empty reference to the loader object, while there must be one", $"El grafo tiene {nulls.Count} objetos cargadores con referencia vacía al objeto cargador, cuando debe haber uno"),
            Severity.High,
            L("The virtual machine has one bootstrap loader: its ClassLoaderData object is created at startup and exists in a single instance. Hidden class loader objects also have no loader object, but their «class mirror holder» flag is set and they are not counted here. A second object without the flag means a structure created bypassing the normal way loaders are created.", "La máquina virtual tiene un único cargador de arranque: su objeto ClassLoaderData se crea al iniciar y existe en una sola instancia. Los objetos de cargadores de clases ocultas tampoco tienen objeto cargador, pero tienen activo el indicador «titular del espejo de clase» y aquí no se cuentan. Un segundo objeto sin el indicador significa una estructura creada eludiendo la vía normal de creación de cargadores."));
        foreach (var cld in nulls)
            f.Add($"0x{cld.Address:X}", L($"classes {cld.Klasses.Count}: ", $"clases {cld.Klasses.Count}: ") +
                                        string.Join(", ", cld.Klasses.Take(8).Select(x => x.Name)));
    }

    private static void ReportHiddenClassLoaders(ScanContext ctx, List<Cld> clds, StringBuilder sb)
    {
        var hits = clds.Where(x => x.LoaderOop != 0 &&
                                   (x.LoaderClass.Contains("+0x", StringComparison.Ordinal) ||
                                    x.LoaderClass.Contains("/0x", StringComparison.Ordinal)))
            .ToList();

        sb.AppendLine(L($"LOADERS WHOSE OWN CLASS IS HIDDEN: {hits.Count}", $"CARGADORES CUYA PROPIA CLASE ES OCULTA: {hits.Count}"));
        foreach (var cld in hits)
            sb.AppendLine(L($"  0x{cld.Address:X}  {cld.LoaderClass}  classes {cld.Klasses.Count}", $"  0x{cld.Address:X}  {cld.LoaderClass}  clases {cld.Klasses.Count}"));
        sb.AppendLine();
        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JAVA",
            L($"{hits.Count} class loaders are themselves hidden classes (classes loaded by them: {hits.Sum(x => x.Klasses.Count)})", $"{hits.Count} cargadores de clases son a su vez clases ocultas (clases cargadas por ellos: {hits.Sum(x => x.Klasses.Count)})"),
            Severity.Critical,
            L("A hidden class is deliberately deprived of a name by which it can be found: its name contains an address, it does not get into name dictionaries, and bytecode cannot refer to it. Normally only lambdas and java.lang.invoke adapters do this — they exist in a single instance and do not load classes. A class loader is the exact opposite: it is a public entry point accessed by name. It is made hidden precisely so that the origin of the code it loads cannot be established by the loader name.", "Una clase oculta carece a propósito de un nombre por el que pueda encontrarse: su nombre contiene una dirección, no entra en los diccionarios de nombres y el bytecode no puede referirse a ella. Normalmente solo lo hacen las lambdas y los adaptadores de java.lang.invoke, que existen en una sola instancia y no cargan clases. Un cargador de clases es justo lo contrario: es un punto público al que se accede por nombre. Se hace oculto precisamente para que el origen del código que carga no pueda establecerse por el nombre del cargador."));
        foreach (var cld in hits)
        {
            f.Add(cld.LoaderClass, L($"ClassLoaderData 0x{cld.Address:X}, classes {cld.Klasses.Count}", $"ClassLoaderData 0x{cld.Address:X}, clases {cld.Klasses.Count}"));
            foreach (var (k, name) in cld.Klasses.Take(12))
                f.Add(L("    loaded by it", "    cargada por él"), $"{name} (Klass 0x{k:X})");
        }
    }

    private static void ReportIntruders(ScanContext ctx, List<Cld> clds, StringBuilder sb)
    {
        var intruders = new List<(Cld Cld, ulong Klass, string Name)>();
        foreach (var cld in clds)
        {
            if (!Privileged(cld)) continue;
            foreach (var (k, name) in cld.Klasses)
            {
                if (JarIndex.IsRuntimeClass(name)) continue;
                if (JarIndex.GeneratedKind(name) is not null) continue;
                if (name.StartsWith("[", StringComparison.Ordinal)) continue;
                intruders.Add((cld, k, name));
            }
        }

        sb.AppendLine(L("CLASSES IN PRIVILEGED LOADERS THAT DO NOT BELONG TO THE JDK IMAGE", "CLASES EN CARGADORES PRIVILEGIADOS QUE NO PERTENECEN A LA IMAGEN DEL JDK"));
        sb.AppendLine(L($"  found: {intruders.Count}", $"  encontradas: {intruders.Count}"));
        foreach (var (cld, k, name) in intruders.Take(500))
            sb.AppendLine(L($"      {name}   (Klass 0x{k:X}, loader {cld.LoaderClass})", $"      {name}   (Klass 0x{k:X}, cargador {cld.LoaderClass})"));
        sb.AppendLine();
        if (intruders.Count == 0) return;

        var jars = ctx.Jars;
        var f = ctx.Report.Report("JAVA",
            L($"{intruders.Count} classes are loaded by a privileged loader although they do not belong to the JDK runtime image", $"{intruders.Count} clases están cargadas por un cargador privilegiado aunque no pertenecen a la imagen del entorno de ejecución del JDK"),
            Severity.Critical,
            L("The bootstrap and platform loaders take classes only from the JDK runtime image, and all their names start with java/, jdk/, sun/, javax/ and the like. Game and mod classes are loaded by the Fabric loader and cannot get here in principle. A class with a foreign name in a privileged loader was put there deliberately, and there are exactly two ways: append an archive with -Xbootclasspath/a: before startup, or define the class directly from native code with a JNI DefineClass call with an empty loader. The second way is the usual work of shellcode that brings its own bytecode: it leaves neither a file on disk nor an entry in the user loader graph.", "Los cargadores de arranque y de plataforma toman clases solo de la imagen del entorno de ejecución del JDK, y todos sus nombres empiezan por java/, jdk/, sun/, javax/ y similares. Las clases del juego y de los mods las carga el cargador de Fabric y en principio no pueden llegar aquí. Una clase con un nombre ajeno en un cargador privilegiado se puso ahí a propósito, y hay exactamente dos formas: añadir un archivo con -Xbootclasspath/a: antes de arrancar, o definir la clase directamente desde código nativo con una llamada JNI DefineClass con cargador vacío. La segunda forma es el trabajo habitual de un shellcode que trae su propio bytecode: no deja ni un archivo en disco ni una entrada en el grafo de cargadores de usuario."));
        foreach (var (cld, k, name) in intruders.Take(60))
        {
            string origin = jars is null ? L("archive index not built", "índice de archivos no construido")
                : NoOriginOnDisk(ctx, name) ? L("NOT IN ARCHIVES", "NO ESTÁ EN LOS ARCHIVOS")
                : jars.Contains(name) ? L("present in archives on disk", "presente en los archivos del disco")
                : jars.OwningPackage(name) is { } p ? L($"not in archives, parent package «{p}» exists", $"no está en los archivos; existe el paquete padre «{p}»")
                : L("origin not established", "origen no establecido");
            f.Add(name, L($"Klass 0x{k:X}, loader {cld.LoaderClass} (0x{cld.Address:X}) [{origin}]", $"Klass 0x{k:X}, cargador {cld.LoaderClass} (0x{cld.Address:X}) [{origin}]"));
        }
    }
}
