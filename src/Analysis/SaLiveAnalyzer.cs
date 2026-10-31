using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class SaLiveAnalyzer
{
    private const uint JVMTI_MAGIC = 0x71EE;
    private const uint DISPOSED_MAGIC = 0xDEFC;
    private const uint BAD_MAGIC = 0xDEAD;

    private static readonly (string Cls, int MaxHits)[] Tracked =
    {
        ("InstanceKlass", 200_000),
        ("InstanceMirrorKlass", 2000),
        ("InstanceRefKlass", 2000),
        ("InstanceClassLoaderKlass", 2000),
        ("InstanceStackChunkKlass", 2000),
        ("ObjArrayKlass", 20_000),
        ("TypeArrayKlass", 2000),
        ("Method", 400_000),
        ("ConstantPool", 200_000),
        ("JvmtiAgentThread", 512),
        ("JvmtiBreakpoint", 4096),
        ("JvmtiVMObjectAllocEventCollector", 512),
        ("JvmtiDynamicCodeEventCollector", 512),
    };

    private static readonly string[] KlassClasses =
    {
        "InstanceKlass", "InstanceMirrorKlass", "InstanceRefKlass",
        "InstanceClassLoaderKlass", "InstanceStackChunkKlass",
        "ObjArrayKlass", "TypeArrayKlass",
    };

    public static List<RawPattern> Prepare(ScanContext ctx)
    {
        var res = new List<RawPattern>();
        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid) return res;

        var vm = VmStructs.Load(ctx.Target, jvm.Base, jvm.Pe);
        ctx.Vm = vm;
        if (vm.Vtables.Count == 0) return res;

        foreach (var (cls, max) in Tracked)
        {
            ulong vt = vm.Vtable(cls);
            if (vt == 0) continue;
            var rp = new RawPattern
            {
                Name = $"vtable {cls} @ 0x{vt:X}",
                Bytes = BitConverter.GetBytes(vt),
                MaxHits = max,
            };
            ctx.VtablePatterns.Add((cls, vt, rp));
            res.Add(rp);
        }
        return res;
    }

    public static void Run(ScanContext ctx, SweepResult sweep)
    {
        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid) return;

        var vm = ctx.Vm ??= VmStructs.Load(ctx.Target, jvm.Base, jvm.Pe);
        ctx.Report.Section(L("HOTSPOT STRUCTURE LAYOUT (live VMStructs)", "DISPOSICIÓN DE ESTRUCTURAS HOTSPOT (VMStructs en vivo)"), vm.Render());

        if (!vm.Valid)
        {
            ctx.Report.Report("JVM",
                L("VMStructs tables in jvm.dll were not parsed — VM structure parsing is unavailable", "No se analizaron las tablas VMStructs de jvm.dll: el análisis de estructuras de la VM no está disponible"),
                Severity.Medium,
                L("gHotSpotVMStructs is an exported table through which HotSpot reports the layout of its internal structures; it exists in every normal jvm.dll build because the Serviceability Agent relies on it. Its absence or unreadability means either an unusual VM build or deliberate corruption of this data to prevent analysis of the virtual machine state.", "gHotSpotVMStructs es una tabla exportada mediante la cual HotSpot informa de la disposición de sus estructuras internas; existe en toda compilación normal de jvm.dll porque el Serviceability Agent depende de ella. Su ausencia o ilegibilidad significa una compilación inusual de la VM o la corrupción deliberada de estos datos para impedir el análisis del estado de la máquina virtual."))
                .Add(L("diagnostics", "diagnóstico"), string.Join("; ", vm.Diagnostics));
            return;
        }

        var idx = BuildIndex(ctx, vm);
        var sb = new StringBuilder();

        var graph = WalkClassLoaderDataGraph(ctx, vm, sb);
        ReportGraph(ctx, vm, graph, sweep, sb);
        ReportOrphans(ctx, vm, graph, idx, sb);
        ReportRedefinedMethods(ctx, vm, graph, sb);
        ReportBreakpoints(ctx, vm, graph, sb);
        ReportJvmtiObjects(ctx, vm, idx, sb);
        WalkJvmtiEnvironments(ctx, vm, jvm, sb);
        ReportJvmtiExportFlags(ctx, vm, sb);
        ReportJvmtiVmStructEntries(ctx, vm, sb);

        ctx.Report.Section(L("LIVE SA: METASPACE, LOADERS, JVMTI", "SA EN VIVO: METASPACE, CARGADORES, JVMTI"), sb.ToString());
    }

    private sealed class VtIndex
    {
        public Dictionary<string, List<ulong>> ByClass = new(StringComparer.Ordinal);
        public bool FromSweep;
        public bool Truncated;
        public long BytesScanned;

        public List<ulong> Get(string cls) =>
            ByClass.TryGetValue(cls, out var l) ? l : new List<ulong>();

        public IEnumerable<ulong> AllKlasses =>
            KlassClasses.SelectMany(Get);
    }

    private static VtIndex BuildIndex(ScanContext ctx, VmStructs vm)
    {
        var idx = new VtIndex();

        if (ctx.VtablePatterns.Count > 0 &&
            ctx.VtablePatterns.Any(p => p.Pattern.TotalHits > 0))
        {
            idx.FromSweep = true;
            foreach (var (cls, _, pat) in ctx.VtablePatterns)
            {
                var list = new List<ulong>(pat.Hits.Count);
                foreach (var (addr, _) in pat.Hits)
                    if ((addr & 7) == 0) list.Add(addr);
                idx.ByClass[cls] = list;
                if (pat.TotalHits > pat.Hits.Count) idx.Truncated = true;
            }
            return idx;
        }

        var wanted = new Dictionary<ulong, string>();
        foreach (var (cls, _) in Tracked)
        {
            ulong vt = vm.Vtable(cls);
            if (vt != 0) wanted[vt] = cls;
            idx.ByClass[cls] = new List<ulong>();
        }
        if (wanted.Count == 0) return idx;

        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateAnyData))
        {
            idx.BytesScanned += ch.Length;
            for (int i = 0; i + 8 <= ch.Length; i += 8)
            {
                ulong v = BitConverter.ToUInt64(ch.Data, i);
                if (v == 0 || !wanted.TryGetValue(v, out var cls)) continue;
                ulong at = ch.Base + (ulong)i;
                var list = idx.ByClass[cls];
                if (list.Count > 0 && list[^1] == at) continue;
                list.Add(at);
            }
        }
        return idx;
    }

    private sealed class KlassRec
    {
        public ulong Address;
        public ulong Cld;
        public string Name = "";
        public uint AccessFlags;
        public byte InitState;
        public ulong Methods;
        public ulong Constants;
        public ulong Breakpoints;
    }

    private sealed class CldRec
    {
        public ulong LoaderOop;
        public ulong Address;
        public string LoaderClass = "";
        public bool HasClassMirrorHolder;
        public List<KlassRec> Klasses = new();
    }

    private sealed class Graph
    {
        public List<CldRec> Clds = new();
        public Dictionary<ulong, KlassRec> Klasses = new();
        public HashSet<ulong> Methods = new();
        public HashSet<ulong> ConstantPools = new();
        public bool Walked;
        public string Problem = "";
        public PageCache Cache = null!;
    }

    private static Graph WalkClassLoaderDataGraph(ScanContext ctx, VmStructs vm, StringBuilder sb)
    {
        var g = new Graph { Cache = new PageCache(ctx.Target, 65536) };
        var c = g.Cache;

        ulong headVar = vm.StaticAddr("ClassLoaderDataGraph", "_head");
        int offNext = vm.Off("ClassLoaderData", "_next");
        int offKlasses = vm.Off("ClassLoaderData", "_klasses");
        int offLoader = vm.Off("ClassLoaderData", "_class_loader");
        int offMirrorHolder = vm.OffAny("ClassLoaderData",
            "_has_class_mirror_holder", "_is_unsafe_anonymous");
        int offNextLink = vm.Off("Klass", "_next_link");
        int offName = vm.Off("Klass", "_name");
        int offCld = vm.Off("Klass", "_class_loader_data");
        int offAcc = vm.Off("Klass", "_access_flags");

        sb.AppendLine(L("WALK OF THE LOADER GRAPH THROUGH VM STRUCTURES", "RECORRIDO DEL GRAFO DE CARGADORES MEDIANTE LAS ESTRUCTURAS DE LA VM"));
        sb.AppendLine($"  ClassLoaderDataGraph::_head : 0x{headVar:X}");
        sb.AppendLine($"  ClassLoaderData::_next      : +0x{offNext:X}   _klasses: +0x{offKlasses:X}");
        sb.AppendLine($"  Klass::_next_link           : +0x{offNextLink:X}   _name: +0x{offName:X}   " +
                      $"_class_loader_data: +0x{offCld:X}");

        if (headVar == 0 || offNext < 0 || offKlasses < 0 || offNextLink < 0 || offName < 0)
        {
            g.Problem = L("VMStructs lacks the fields needed to walk the loader graph", "en VMStructs faltan los campos necesarios para recorrer el grafo de cargadores");
            sb.AppendLine("  " + g.Problem);
            sb.AppendLine();
            return g;
        }

        int offIkMethods = vm.Off("InstanceKlass", "_methods");
        int offIkConst = vm.Off("InstanceKlass", "_constants");
        int offIkInit = vm.Off("InstanceKlass", "_init_state");
        int offIkBp = vm.Off("InstanceKlass", "_breakpoints");

        ulong cld = c.U64(headVar);
        int guard = 0;
        var seenCld = new HashSet<ulong>();

        while (cld is >= 0x10000 and <= 0x7FFFFFFFFFFF && guard++ < 100_000)
        {
            if (!seenCld.Add(cld)) break;
            var rec = new CldRec { Address = cld };

            if (offLoader >= 0)
            {
                ulong handle = c.U64(cld + (ulong)offLoader);
                ulong oop = handle == 0 ? 0 : c.U64(handle);
                rec.LoaderOop = oop;
                rec.LoaderClass = oop == 0
                    ? L("<bootstrap loader>", "<cargador de arranque>")
                    : NameOfOopKlass(c, vm, oop) ?? L("<undetermined>", "<no determinado>");
            }
            if (offMirrorHolder >= 0)
                rec.HasClassMirrorHolder = ctx.Target.ReadU8(cld + (ulong)offMirrorHolder) != 0;

            ulong k = c.U64(cld + (ulong)offKlasses);
            int kguard = 0;
            while (k is >= 0x10000 and <= 0x7FFFFFFFFFFF && kguard++ < 200_000)
            {
                if (g.Klasses.ContainsKey(k)) break;

                var kr = new KlassRec
                {
                    Address = k,
                    Cld = offCld >= 0 ? c.U64(k + (ulong)offCld) : cld,
                    Name = ReadSymbol(c, vm, c.U64(k + (ulong)offName)) ?? "",
                    AccessFlags = offAcc >= 0 ? c.U32(k + (ulong)offAcc) : 0,
                };
                if (offIkMethods >= 0) kr.Methods = c.U64(k + (ulong)offIkMethods);
                if (offIkConst >= 0) kr.Constants = c.U64(k + (ulong)offIkConst);
                if (offIkInit >= 0) kr.InitState = (byte)(c.U32(k + (ulong)offIkInit) & 0xFF);
                if (offIkBp >= 0) kr.Breakpoints = c.U64(k + (ulong)offIkBp);

                g.Klasses[k] = kr;
                rec.Klasses.Add(kr);
                k = c.U64(k + (ulong)offNextLink);
            }

            g.Clds.Add(rec);
            cld = c.U64(cld + (ulong)offNext);
        }

        foreach (var kr in g.Klasses.Values)
        {
            if (kr.Constants is >= 0x10000 and <= 0x7FFFFFFFFFFF)
                g.ConstantPools.Add(kr.Constants);
            foreach (ulong m in ReadMetaArray(c, kr.Methods, 200_000))
                g.Methods.Add(m);
        }

        g.Walked = g.Clds.Count > 0;
        foreach (var kv in g.Klasses) ctx.LiveKlasses[kv.Key] = kv.Value.Name;
        foreach (var m in g.Methods) ctx.LiveMethods.Add(m);
        foreach (var rec in g.Clds)
        {
            ctx.ClassLoaderDatas.Add(rec.Address);
        }

        sb.AppendLine(L($"  loaders (ClassLoaderData): {g.Clds.Count}", $"  cargadores (ClassLoaderData): {g.Clds.Count}"));
        sb.AppendLine(L($"  classes in the graph      : {g.Klasses.Count}", $"  clases en el grafo         : {g.Klasses.Count}"));
        sb.AppendLine(L($"  methods of these classes  : {g.Methods.Count}", $"  métodos de estas clases    : {g.Methods.Count}"));
        sb.AppendLine();
        return g;
    }

    private static IEnumerable<ulong> ReadMetaArray(PageCache c, ulong array, int cap)
    {
        if (array is < 0x10000 or > 0x7FFFFFFFFFFF) yield break;
        int len = (int)c.U32(array);
        if (len is <= 0 or > 200_000) yield break;
        for (int i = 0; i < len && i < cap; i++)
        {
            ulong v = c.U64(array + 8 + (ulong)i * 8);
            if (v is >= 0x10000 and <= 0x7FFFFFFFFFFF) yield return v;
        }
    }

    private static string? ReadSymbol(PageCache c, VmStructs vm, ulong sym)
    {
        if (sym is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        int offLen = vm.Off("Symbol", "_length");
        int offBody = vm.OffAny("Symbol", "_body[0]", "_body");
        if (offLen < 0) offLen = 4;
        if (offBody < 0) offBody = 6;

        Span<byte> head = stackalloc byte[8];
        if (!c.Read(sym, head)) return null;
        int len = BitConverter.ToUInt16(head[offLen..]);
        if (len is < 1 or > 512) return null;
        var body = new byte[len];
        if (!c.Read(sym + (ulong)offBody, body)) return null;
        return JavaNames.DecodeModifiedUtf8(body);
    }

    private static ulong KlassOfOop(PageCache c, VmStructs vm, ulong oop)
    {
        int off = vm.OffAny("oopDesc", "_metadata._compressed_klass", "_metadata._klass");
        if (off < 0) off = 8;
        var f = vm.Field("oopDesc", "_metadata._compressed_klass");
        if (f is null)
            return c.U64(oop + (ulong)off);

        ulong baseAddr = 0;
        int shift = 0;
        ulong bv = vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._base"),
            ("Universe", "_narrow_klass._base"));
        ulong sv = vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._shift"),
            ("Universe", "_narrow_klass._shift"));
        if (bv != 0) baseAddr = c.U64(bv);
        if (sv != 0) shift = (int)c.U32(sv);

        uint narrow = c.U32(oop + (ulong)off);
        if (narrow == 0) return 0;
        return baseAddr + ((ulong)narrow << shift);
    }

    private static string? NameOfOopKlass(PageCache c, VmStructs vm, ulong oop)
    {
        ulong k = KlassOfOop(c, vm, oop);
        if (k is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        int offName = vm.Off("Klass", "_name");
        return offName < 0 ? null : ReadSymbol(c, vm, c.U64(k + (ulong)offName));
    }

    private static void ReportGraph(ScanContext ctx, VmStructs vm, Graph g,
        SweepResult sweep, StringBuilder sb)
    {
        if (!g.Walked)
        {
            ctx.Report.Report("JVM",
                L("The class loader graph was not walked through VM structures", "No se recorrió el grafo de cargadores de clases mediante las estructuras de la VM"),
                Severity.Low,
                L("The structure layout was obtained, but ClassLoaderDataGraph could not be walked. The other class checks (bytecode in memory and archives) work independently.", "Se obtuvo la disposición de estructuras, pero no se pudo recorrer ClassLoaderDataGraph. Las demás comprobaciones de clases (bytecode en memoria y archivos) funcionan de forma independiente."))
                .Add(L("reason", "motivo"), g.Problem.Length > 0 ? g.Problem : L("loader chain is empty", "la cadena de cargadores está vacía"));
            return;
        }

        sb.AppendLine(L("LOADERS (by ClassLoaderDataGraph):", "CARGADORES (según ClassLoaderDataGraph):"));
        sb.AppendLine(L($"{"CLD ADDRESS",-18} {"CLASSES",-9} {"HIDDEN",-7} LOADER CLASS", $"{"DIRECCIÓN CLD",-18} {"CLASES",-9} {"OCULTO",-7} CLASE DEL CARGADOR"));
        sb.AppendLine(new string('-', 120));
        var shown = g.Clds.OrderByDescending(x => x.Klasses.Count).Take(80).ToList();
        foreach (var cld in shown)
            sb.AppendLine(L($"0x{cld.Address:X16} {cld.Klasses.Count,-9} {(cld.HasClassMirrorHolder ? "yes" : "-"),-7} {cld.LoaderClass}", $"0x{cld.Address:X16} {cld.Klasses.Count,-9} {(cld.HasClassMirrorHolder ? "sí" : "-"),-7} {cld.LoaderClass}"));
        if (g.Clds.Count > shown.Count)
            sb.AppendLine(L($"  ... and {g.Clds.Count - shown.Count} more loaders with one or two classes (hidden classes: lambdas, method handles)", $"  ... y {g.Clds.Count - shown.Count} cargadores más con una o dos clases (clases ocultas: lambdas, method handles)"));
        sb.AppendLine();

        var f = ctx.Report.Report("JVM",
            L($"The VM loader graph was walked through structures: {g.Clds.Count} loaders, {g.Klasses.Count} classes, {g.Methods.Count} methods", $"Se recorrió el grafo de cargadores de la VM mediante estructuras: {g.Clds.Count} cargadores, {g.Klasses.Count} clases, {g.Methods.Count} métodos"),
            Severity.Info,
            L("This enumeration was made from the internal lists of the virtual machine itself (ClassLoaderDataGraph → ClassLoaderData → Klass::_next_link), not by searching for bytecode in memory. The list is authoritative: it holds exactly what the JVM considers loaded right now. Comparing this list with the bytecode found in memory shows classes that were defined but are not in the graph.", "Esta enumeración se hizo a partir de las listas internas de la propia máquina virtual (ClassLoaderDataGraph → ClassLoaderData → Klass::_next_link), no buscando bytecode en memoria. La lista es fiable: contiene exactamente lo que la JVM considera cargado en este momento. Comparar esta lista con el bytecode encontrado en memoria muestra las clases que se definieron pero no están en el grafo."));
        foreach (var cld in g.Clds.OrderByDescending(x => x.Klasses.Count).Take(48))
            f.Add($"CLD 0x{cld.Address:X}",
                L($"{cld.Klasses.Count} classes, loader {cld.LoaderClass}", $"{cld.Klasses.Count} clases, cargador {cld.LoaderClass}") +
                (cld.HasClassMirrorHolder ? L(", isolated (hidden class)", ", aislado (clase oculta)") : ""));

        var hidden = g.Clds.Where(x => x.HasClassMirrorHolder).ToList();
        sb.AppendLine(L($"Hidden class loaders (has_class_mirror_holder): {hidden.Count}", $"Cargadores de clases ocultas (has_class_mirror_holder): {hidden.Count}"));
        var hiddenNames = hidden.SelectMany(h => h.Klasses).Select(k => k.Name)
            .Where(n => n.Length > 0).ToList();
        foreach (var n in hiddenNames.Take(80)) sb.AppendLine("    " + n);
        sb.AppendLine();

        if (sweep.Classes.Count > 0)
        {
            var live = new HashSet<string>(g.Klasses.Values.Select(k => k.Name.Replace('.', '/')),
                StringComparer.Ordinal);
            var ghosts = sweep.Classes.Values
                .Where(x => x.Name.Length > 0 && !live.Contains(x.Name))
                .ToList();

            sb.AppendLine(L($"Classes found as bytecode in memory: {sweep.Classes.Count}", $"Clases encontradas como bytecode en memoria: {sweep.Classes.Count}"));
            sb.AppendLine(L($"Missing from the live VM graph: {ghosts.Count}", $"Ausentes del grafo vivo de la VM: {ghosts.Count}"));
            foreach (var x in ghosts.Take(120))
                sb.AppendLine($"    0x{x.Address:X}  {x.Name}" +
                              (x.Occurrences > 1 ? L($"  (copies: {x.Occurrences})", $"  (copias: {x.Occurrences})") : ""));
            sb.AppendLine();

            if (ghosts.Count > 0)
            {
                var f2 = ctx.Report.Report("JVM",
                    L($"{ghosts.Count} classes are present in memory as bytecode but missing from the live VM loader graph", $"{ghosts.Count} clases están en memoria como bytecode pero faltan en el grafo vivo de cargadores de la VM"),
                    Severity.Info,
                    L("The bytecode of a class gets into memory when it is defined and stays there until the buffer is reused. A class whose bytecode is in memory but which is not in ClassLoaderDataGraph was defined and unloaded (or defined as hidden). Normally this is what lambdas, generated proxies and the result of Mixin look like. A cheat class removed after an «unhook» looks the same: look at the names.", "El bytecode de una clase llega a la memoria al definirse y permanece ahí hasta que el búfer se reutiliza. Una clase cuyo bytecode está en memoria pero que no está en ClassLoaderDataGraph se definió y se descargó (o se definió como oculta). Normalmente así se ven las lambdas, los proxies generados y el resultado de Mixin. Una clase de cheat retirada tras un «unhook» se ve igual: fíjese en los nombres."));
                foreach (var x in ghosts.Take(60))
                    f2.Add(x.Name, L($"0x{x.Address:X}, class file version {x.MajorVersion}", $"0x{x.Address:X}, versión del archivo de clase {x.MajorVersion}") +
                                   (x.Occurrences > 1 ? L($", copies in memory: {x.Occurrences}", $", copias en memoria: {x.Occurrences}") : ""));
            }
        }

    }

    private static void ReportOrphans(ScanContext ctx, VmStructs vm, Graph g, VtIndex idx,
        StringBuilder sb)
    {
        var c = g.Cache;
        int offName = vm.Off("Klass", "_name");
        int offCld = vm.Off("Klass", "_class_loader_data");

        var allKlassObjs = idx.AllKlasses.Distinct().ToList();
        foreach (ulong a in allKlassObjs)
        {
            if (ctx.AllKlassObjects.ContainsKey(a)) continue;
            ctx.AllKlassObjects[a] = g.Klasses.TryGetValue(a, out var kr)
                ? kr.Name
                : offName < 0 ? "" : ReadSymbol(c, vm, c.U64(a + (ulong)offName)) ?? "";
        }

        var orphanKlasses = g.Walked
            ? allKlassObjs.Where(a => !g.Klasses.ContainsKey(a)).ToList()
            : new List<ulong>();

        var allMethods = idx.Get("Method");
        var orphanMethods = g.Walked
            ? allMethods.Where(a => !g.Methods.Contains(a)).ToList()
            : new List<ulong>();

        var allPools = idx.Get("ConstantPool");
        var orphanPools = g.Walked
            ? allPools.Where(a => !g.ConstantPools.Contains(a)).ToList()
            : new List<ulong>();

        sb.AppendLine(L("METASPACE OBJECTS (identified by the exact vtable address):", "OBJETOS DEL METASPACE (identificados por la dirección exacta de la vtable):"));
        sb.AppendLine(L($"  source: {(idx.FromSweep ? "full memory scan" : "own pass")}", $"  fuente: {(idx.FromSweep ? "escaneo completo de memoria" : "pasada propia")}") +
                      (idx.Truncated ? L(" (lists truncated by the limit)", " (listas truncadas por el límite)") : ""));
        foreach (var (cls, _) in Tracked)
        {
            var list = idx.Get(cls);
            if (list.Count == 0) continue;
            sb.AppendLine($"  {cls,-36} {list.Count}");
        }
        sb.AppendLine();
        sb.AppendLine(L($"  Klass objects total: {allKlassObjs.Count}, outside the loader graph: {orphanKlasses.Count}", $"  objetos Klass en total: {allKlassObjs.Count}, fuera del grafo de cargadores: {orphanKlasses.Count}"));
        sb.AppendLine(L($"  Method objects total: {allMethods.Count}, outside live classes: {orphanMethods.Count}", $"  objetos Method en total: {allMethods.Count}, fuera de clases vivas: {orphanMethods.Count}"));
        sb.AppendLine(L($"  ConstantPool total: {allPools.Count}, outside live classes: {orphanPools.Count}", $"  ConstantPool en total: {allPools.Count}, fuera de clases vivas: {orphanPools.Count}"));
        sb.AppendLine();

        if (!g.Walked) return;

        var described = new List<(ulong Addr, string Name, ulong Cld, bool CldLive)>();
        var liveClds = g.Clds.Select(x => x.Address).ToHashSet();
        foreach (ulong a in orphanKlasses.Take(4000))
        {
            string name = offName < 0 ? "" : ReadSymbol(c, vm, c.U64(a + (ulong)offName)) ?? "";
            ulong cld = offCld < 0 ? 0 : c.U64(a + (ulong)offCld);
            described.Add((a, name, cld, liveClds.Contains(cld)));
        }

        foreach (var d in described.Take(200))
            sb.AppendLine(L($"    orphaned Klass 0x{d.Addr:X}  «{Short(d.Name)}»  CLD 0x{d.Cld:X} ({(d.CldLive ? "live" : "NOT in the graph")})", $"    Klass huérfano 0x{d.Addr:X}  «{Short(d.Name)}»  CLD 0x{d.Cld:X} ({(d.CldLive ? "vivo" : "NO está en el grafo")})") +
                          (IsRuntimeNoise(d.Name) ? L("  [normal VM garbage]", "  [basura normal de la VM]") : ""));
        if (described.Count > 0) sb.AppendLine();

        if (described.Count > 0)
        {
            var noisy = described.Where(x => IsRuntimeNoise(x.Name)).ToList();
            var hard = described.Where(x => !IsRuntimeNoise(x.Name)).ToList();

            var f = ctx.Report.Report("JVM",
                L($"{orphanKlasses.Count} Klass objects in the metaspace are not reachable from the loader graph (runtime-generated: {noisy.Count}, with a meaningful name: {hard.Count})", $"{orphanKlasses.Count} objetos Klass del metaspace no son alcanzables desde el grafo de cargadores (generados por el entorno de ejecución: {noisy.Count}, con nombre significativo: {hard.Count})"),
                hard.Count > 0 ? Severity.High : Severity.Info,
                L("The class object was identified by the exact address of the virtual function table exported by jvm.dll itself — this is not a heuristic. A live VM keeps all its classes in ClassLoaderData lists; a class that cannot be reached through these lists is metadata left after a loader was unloaded or after a class was redefined (RedefineClasses/RetransformClasses). IMPORTANT for interpretation: such objects also exist in a clean game — these are lambdas and other hidden classes whose memory the metaspace has not reused yet (verified on a clean client). That is why classes with a meaningful name that does not look runtime-generated are counted separately: those require an explanation, because cheat classes after an «unhook» look exactly like that.", "El objeto de clase se identificó por la dirección exacta de la tabla de funciones virtuales que exporta la propia jvm.dll: no es una heurística. Una VM viva mantiene todas sus clases en listas ClassLoaderData; una clase a la que no se puede llegar por estas listas son metadatos que quedaron tras descargar un cargador o tras redefinir una clase (RedefineClasses/RetransformClasses). IMPORTANTE para la interpretación: estos objetos también existen en una partida limpia; son lambdas y otras clases ocultas cuya memoria el metaspace aún no reutilizó (comprobado en un cliente limpio). Por eso se cuentan aparte las clases con un nombre significativo que no parece generado por el entorno de ejecución: esas sí requieren explicación, porque las clases de un cheat tras un «unhook» se ven exactamente así."));
            foreach (var d in hard.Take(60))
                f.Add(d.Name.Length > 0 ? Short(d.Name) : $"0x{d.Addr:X}",
                    L($"object 0x{d.Addr:X}, ClassLoaderData 0x{d.Cld:X} ({(d.CldLive ? "loader alive" : "loader not in the graph")})", $"objeto 0x{d.Addr:X}, ClassLoaderData 0x{d.Cld:X} ({(d.CldLive ? "cargador vivo" : "cargador ausente del grafo")})"));
            if (hard.Count == 0)
                f.Block(L("Examples (all identified as runtime-generated)", "Ejemplos (todos identificados como generados por el entorno de ejecución)"),
                    string.Join("\n", noisy.Take(24).Select(x => "  " + Short(x.Name))));
        }

        if (orphanMethods.Count > 0)
        {
            var holders = ResolveMethodHolders(c, vm, orphanMethods.Take(2000));
            var interesting = holders.Where(x => !IsRuntimeMethodHolder(x.Value)).ToList();

            sb.AppendLine(L("Owner classes of orphaned methods:", "Clases propietarias de métodos huérfanos:"));
            foreach (var kv in holders.GroupBy(x => x.Value).OrderByDescending(x => x.Count())
                         .Take(40))
                sb.AppendLine($"    {kv.Count(),6}  {Short(kv.Key)}");
            sb.AppendLine();

            var f = ctx.Report.Report("JVM",
                L($"{orphanMethods.Count} Method objects in the metaspace belong to no live class (with a meaningful owner class: {interesting.Count})", $"{orphanMethods.Count} objetos Method del metaspace no pertenecen a ninguna clase viva (con clase propietaria significativa: {interesting.Count})"),
                interesting.Count >= 8 ? Severity.Medium : Severity.Info,
                L("Every live class keeps its methods in the InstanceKlass::_methods array. A Method object that is in no such array is either a method of an unloaded class or an OLD VERSION of a method left by RedefineClasses/RetransformClasses: when a class is redefined, the JVM does not delete the previous methods while stack frames and compiled code may still refer to them. The owner class is taken via the Method → ConstMethod → ConstantPool → _pool_holder chain, so it is visible exactly which classes left these methods behind. Some such objects also exist in a clean game (lambdas and hidden classes); they are counted separately.", "Cada clase viva guarda sus métodos en el array InstanceKlass::_methods. Un objeto Method que no está en ningún array así es un método de una clase descargada o una VERSIÓN ANTIGUA de un método que dejó RedefineClasses/RetransformClasses: al redefinir una clase, la JVM no elimina los métodos anteriores mientras puedan referenciarlos marcos de pila y código compilado. La clase propietaria se obtiene por la cadena Method → ConstMethod → ConstantPool → _pool_holder, así que se ve exactamente qué clases dejaron estos métodos. Algunos de estos objetos también existen en una partida limpia (lambdas y clases ocultas); se cuentan aparte."));
            f.Add(L("Method objects total", "objetos Method en total"), allMethods.Count.ToString());
            f.Add(L("outside live classes", "fuera de clases vivas"), orphanMethods.Count.ToString());
            foreach (var g2 in interesting.GroupBy(x => x.Value)
                         .OrderByDescending(x => x.Count()).Take(40))
                f.Add(Short(g2.Key), L($"{g2.Count()} orphaned methods", $"{g2.Count()} métodos huérfanos"));
        }

        if (orphanPools.Count > 0)
        {
            ctx.Report.Report("JVM",
                    L($"{orphanPools.Count} constant pools in the metaspace belong to no live class", $"{orphanPools.Count} pools de constantes del metaspace no pertenecen a ninguna clase viva"),
                    Severity.Info,
                    L("The ConstantPool of a live class is always reachable through InstanceKlass::_constants. An orphaned pool remains after a class redefinition (the new class version has its own pool, the old one lives while old methods refer to it) and after classes are unloaded. A clean game also has such pools — lambdas and hidden classes leave them — so look not at the number itself but at the list of owner classes of orphaned methods above.", "El ConstantPool de una clase viva siempre es alcanzable mediante InstanceKlass::_constants. Un pool huérfano queda tras redefinir una clase (la versión nueva tiene su propio pool y el antiguo vive mientras lo referencien métodos antiguos) y tras descargar clases. Una partida limpia también tiene estos pools, que dejan las lambdas y las clases ocultas, así que no mire el número en sí, sino la lista de clases propietarias de los métodos huérfanos de arriba."))
                .Add(L("pools total", "pools en total"), allPools.Count.ToString())
                .Add(L("orphaned", "huérfanos"), orphanPools.Count.ToString())
                .Block(L("Addresses (first 64)", "Direcciones (las primeras 64)"),
                    string.Join("\n", orphanPools.Take(64).Select(a => $"  0x{a:X}")));
        }
    }

    internal static Dictionary<ulong, string> ResolveMethodHolders(PageCache c, VmStructs vm,
        IEnumerable<ulong> methods)
    {
        var res = new Dictionary<ulong, string>();
        int offConstMethod = vm.Off("Method", "_constMethod");
        int offConstants = vm.Off("ConstMethod", "_constants");
        int offHolder = vm.Off("ConstantPool", "_pool_holder");
        int offName = vm.Off("Klass", "_name");
        if (offConstMethod < 0 || offConstants < 0 || offHolder < 0 || offName < 0) return res;

        foreach (ulong m in methods)
        {
            ulong cm = c.U64(m + (ulong)offConstMethod);
            if (cm is < 0x10000 or > 0x7FFFFFFFFFFF) { res[m] = L("<undetermined>", "<no determinado>"); continue; }
            ulong cp = c.U64(cm + (ulong)offConstants);
            if (cp is < 0x10000 or > 0x7FFFFFFFFFFF) { res[m] = L("<undetermined>", "<no determinado>"); continue; }
            ulong k = c.U64(cp + (ulong)offHolder);
            if (k is < 0x10000 or > 0x7FFFFFFFFFFF) { res[m] = L("<undetermined>", "<no determinado>"); continue; }
            res[m] = ReadSymbol(c, vm, c.U64(k + (ulong)offName)) ?? L("<undetermined>", "<no determinado>");
        }
        return res;
    }

    private static bool IsRuntimeNoise(string name)
    {
        if (name.Length == 0) return true;
        if (name.Contains('?')) return true;
        if (JavaNames.LooksLikeFreedMemory(name)) return true;
        if (name.Contains("$$Lambda", StringComparison.Ordinal)) return true;
        if (name.Contains("/LambdaForm$", StringComparison.Ordinal)) return true;
        if (name.Contains("$$Proxy", StringComparison.Ordinal)) return true;
        if (name.StartsWith("jdk/proxy", StringComparison.Ordinal)) return true;
        if (name.StartsWith("com/sun/proxy/", StringComparison.Ordinal)) return true;
        if (name.Contains("$$InjectedInvoker", StringComparison.Ordinal)) return true;
        if (name.Contains("Lambda$", StringComparison.Ordinal)) return true;
        return false;
    }

    internal static bool IsRuntimeMethodHolder(string name) =>
        IsRuntimeNoise(name) ||
        name is "java/lang/invoke/MethodHandle" or "java/lang/invoke/VarHandle";

    private static string Short(string s) => s.Length <= 120 ? s : s[..117] + "...";

    private static readonly (uint Bit, string Name, string Why)[] MethodInternalFlags =
    {
        (0x00008000, "JVM_ACC_IS_DELETED",
            L("method deleted during class redefinition via RedefineClasses", "método eliminado al redefinir la clase con RedefineClasses")),
        (0x00010000, "JVM_ACC_IS_OLD",
            L("method replaced during class redefinition — this is its OLD version", "método sustituido al redefinir la clase: es su versión ANTIGUA")),
        (0x00020000, "JVM_ACC_IS_OBSOLETE",
            L("method declared obsolete after RedefineClasses", "método declarado obsoleto tras RedefineClasses")),
        (0x00040000, "JVM_ACC_IS_PREFIXED_NATIVE",
            L("JVMTI renamed a native method (SetNativeMethodPrefix) — an agent technique for intercepting native methods", "JVMTI renombró un método nativo (SetNativeMethodPrefix): técnica de un agente para interceptar métodos nativos")),
        (0x00080000, "JVM_ACC_ON_STACK",
            L("the method was on the stack at the moment of class redefinition", "el método estaba en la pila en el momento de redefinir la clase")),
    };

    private static void ReportRedefinedMethods(ScanContext ctx, VmStructs vm, Graph g,
        StringBuilder sb)
    {
        if (!g.Walked) return;
        int offAcc = vm.Off("Method", "_access_flags");
        int offConst = vm.Off("Method", "_constMethod");
        if (offAcc < 0) return;

        var c = g.Cache;
        var hits = new List<(ulong Addr, uint Flags, string Klass)>();
        var byKlass = new Dictionary<ulong, string>();
        foreach (var kr in g.Klasses.Values) byKlass[kr.Address] = kr.Name;

        foreach (var kr in g.Klasses.Values)
        {
            foreach (ulong m in ReadMetaArray(c, kr.Methods, 100_000))
            {
                uint fl = c.U32(m + (ulong)offAcc);
                uint internalBits = fl & 0x000F8000;
                if (internalBits == 0) continue;
                hits.Add((m, fl, kr.Name));
                if (hits.Count > 4000) break;
            }
            if (hits.Count > 4000) break;
        }

        sb.AppendLine(L("REDEFINITION FLAGS ON LIVE METHODS:", "BANDERAS DE REDEFINICIÓN EN MÉTODOS VIVOS:"));
        sb.AppendLine(L($"  methods with internal redefine/prefix flags: {hits.Count}", $"  métodos con banderas internas redefine/prefix: {hits.Count}"));
        foreach (var h in hits.Take(120))
            sb.AppendLine(L($"    0x{h.Addr:X}  flags=0x{h.Flags:X8}  {DecodeMethodFlags(h.Flags)}  in class {h.Klass}", $"    0x{h.Addr:X}  flags=0x{h.Flags:X8}  {DecodeMethodFlags(h.Flags)}  en la clase {h.Klass}"));
        sb.AppendLine();

        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            L($"{hits.Count} methods are marked with internal redefinition flags (RedefineClasses / RetransformClasses / SetNativeMethodPrefix)", $"{hits.Count} métodos están marcados con banderas internas de redefinición (RedefineClasses / RetransformClasses / SetNativeMethodPrefix)"),
            Severity.Critical,
            L("A method\'s AccessFlags contain not only flags from the class file but also service bits of the VM itself. The IS_OLD, IS_OBSOLETE and IS_DELETED bits are set ONLY by RedefineClasses and RetransformClasses, and IS_PREFIXED_NATIVE by SetNativeMethodPrefix. All of these are JVMTI capabilities: ordinary Java code cannot reach them, and no normal Minecraft component uses them. The flags remain on metadata objects forever, so they are visible even after the agent has finished and detached.", "Los AccessFlags de un método contienen no solo las banderas del archivo de clase, sino también bits de servicio de la propia VM. Los bits IS_OLD, IS_OBSOLETE e IS_DELETED los ponen SOLO RedefineClasses y RetransformClasses, e IS_PREFIXED_NATIVE la función SetNativeMethodPrefix. Todo ello son capacidades de JVMTI: el código Java normal no llega a ellas y ningún componente normal de Minecraft las usa. Las banderas permanecen para siempre en los objetos de metadatos, así que se ven incluso después de que el agente termine y se desconecte."));
        foreach (var h in hits.Take(80))
            f.Add($"0x{h.Addr:X}", L($"{DecodeMethodFlags(h.Flags)} — class {h.Klass}", $"{DecodeMethodFlags(h.Flags)}: clase {h.Klass}"));
        f.Add(L("flag explanation", "explicación de las banderas"), string.Join("; ",
            MethodInternalFlags.Where(x => hits.Any(h => (h.Flags & x.Bit) != 0))
                .Select(x => $"{x.Name}: {x.Why}")));
        _ = offConst;
    }

    private static string DecodeMethodFlags(uint fl)
    {
        var parts = MethodInternalFlags.Where(x => (fl & x.Bit) != 0).Select(x => x.Name).ToList();
        return parts.Count == 0 ? "-" : string.Join("|", parts);
    }

    private static void ReportMethodBreakpointCounters(ScanContext ctx, VmStructs vm, Graph g,
        StringBuilder sb)
    {
        int offCounters = vm.Off("Method", "_method_counters");
        int offNum = vm.Off("MethodCounters", "_number_of_breakpoints");
        sb.AppendLine(L("METHOD BREAKPOINT COUNTERS", "CONTADORES DE PUNTOS DE INTERRUPCIÓN DE MÉTODOS"));
        if (offCounters < 0 || offNum < 0)
        {
            sb.AppendLine(L("  MethodCounters fields are not described in this build — check skipped.", "  los campos de MethodCounters no están descritos en esta compilación: comprobación omitida."));
            sb.AppendLine();
            return;
        }

        var c = g.Cache;
        var hits = new List<(string Klass, ulong Method, int Count)>();
        int withCounters = 0;

        foreach (var kr in g.Klasses.Values)
        {
            foreach (ulong m in ReadMetaArray(c, kr.Methods, 100_000))
            {
                ulong mc = c.U64(m + (ulong)offCounters);
                if (mc is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                withCounters++;
                int n = (int)(c.U32(mc + (ulong)offNum) & 0xFFFF);
                if (n is <= 0 or > 4096) continue;
                hits.Add((kr.Name, m, n));
                if (hits.Count > 512) break;
            }
            if (hits.Count > 512) break;
        }

        sb.AppendLine(L($"  methods with counters  : {withCounters}", $"  métodos con contadores : {withCounters}"));
        sb.AppendLine(L($"  with a non-zero counter: {hits.Count}", $"  con contador no nulo   : {hits.Count}"));
        foreach (var h in hits.Take(64))
            sb.AppendLine(L($"      {h.Klass}  Method 0x{h.Method:X}  breakpoints: {h.Count}", $"      {h.Klass}  Method 0x{h.Method:X}  puntos de interrupción: {h.Count}"));
        sb.AppendLine();
        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            L($"{hits.Count} methods have a non-zero JVMTI breakpoint counter", $"{hits.Count} métodos tienen un contador de puntos de interrupción JVMTI distinto de cero"),
            Severity.Critical,
            L("A method\'s breakpoint counter is incremented only by the JVMTI function SetBreakpoint. Neither Java code nor the virtual machine itself can touch it. This is a second record of the same event, independent of the class breakpoint list — and it survives the agent\'s departure more reliably: the class list is cleared on detach, while the method counter remains. A non-zero value means the execution of specific game methods was intercepted.", "El contador de puntos de interrupción de un método solo lo incrementa la función JVMTI SetBreakpoint. Ni el código Java ni la propia máquina virtual pueden tocarlo. Es un segundo registro del mismo evento, independiente de la lista de puntos de interrupción de la clase, y sobrevive a la marcha del agente con más fiabilidad: la lista de la clase se vacía al desconectar, mientras el contador del método permanece. Un valor no nulo significa que se interceptó la ejecución de métodos concretos del juego."));
        foreach (var h in hits.Take(48))
            f.Add(h.Klass, L($"Method 0x{h.Method:X}, breakpoints: {h.Count}", $"Method 0x{h.Method:X}, puntos de interrupción: {h.Count}"));
    }

    private static void ReportBreakpoints(ScanContext ctx, VmStructs vm, Graph g, StringBuilder sb)
    {
        if (!g.Walked) return;
        ReportMethodBreakpointCounters(ctx, vm, g, sb);
        if (vm.Off("InstanceKlass", "_breakpoints") < 0)
        {
            sb.AppendLine(L("The InstanceKlass::_breakpoints field is not described in this build — the JVMTI breakpoint check was not performed.", "El campo InstanceKlass::_breakpoints no está descrito en esta compilación: no se hizo la comprobación de puntos de interrupción JVMTI."));
            sb.AppendLine();
            return;
        }

        var withBp = g.Klasses.Values.Where(k => k.Breakpoints is >= 0x10000 and <= 0x7FFFFFFFFFFF)
            .ToList();

        sb.AppendLine(L("JVMTI BREAKPOINTS:", "PUNTOS DE INTERRUPCIÓN JVMTI:"));
        sb.AppendLine(L($"  classes with non-empty _breakpoints   : {withBp.Count}", $"  clases con _breakpoints no vacío       : {withBp.Count}"));
        foreach (var k in withBp.Take(64))
            sb.AppendLine($"    {k.Name}  (BreakpointInfo* = 0x{k.Breakpoints:X})");
        sb.AppendLine();

        if (withBp.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            L($"{withBp.Count} classes have JVMTI breakpoints set (InstanceKlass::_breakpoints is not empty)", $"{withBp.Count} clases tienen puntos de interrupción JVMTI (InstanceKlass::_breakpoints no está vacío)"),
            Severity.Critical,
            L("A class\'s BreakpointInfo list is filled only by the JVMTI function SetBreakpoint. Neither the JVM itself nor Java code can do this: it is an agent capability requiring can_generate_breakpoint_events. A breakpoint means someone intercepted the execution of a specific game method — a typical technique for reading and replacing values at runtime.", "La lista BreakpointInfo de una clase solo la rellena la función JVMTI SetBreakpoint. Ni la propia JVM ni el código Java pueden hacerlo: es una capacidad de agente que requiere can_generate_breakpoint_events. Un punto de interrupción significa que alguien interceptó la ejecución de un método concreto del juego: una técnica típica para leer y sustituir valores en tiempo de ejecución."));
        foreach (var k in withBp.Take(48))
            f.Add(k.Name.Length > 0 ? k.Name : $"0x{k.Address:X}",
                $"InstanceKlass 0x{k.Address:X}, BreakpointInfo* 0x{k.Breakpoints:X}");
    }

    private static readonly (string Cls, Severity Sev, string Why)[] JvmtiObjectClasses =
    {
        ("JvmtiAgentThread", Severity.Critical,
            L("JvmtiAgentThread is the object of a thread created by the JVMTI function RunAgentThread. Only an agent creates such a thread; neither the JVM nor Minecraft does. The object lives in the C++ heap and stays there after the thread ends.", "JvmtiAgentThread es el objeto de un hilo creado por la función JVMTI RunAgentThread. Solo un agente crea un hilo así; ni la JVM ni Minecraft lo hacen. El objeto vive en el heap de C++ y permanece ahí después de que el hilo termine.")),
        ("JvmtiBreakpoint", Severity.Critical,
            L("JvmtiBreakpoint is a breakpoint record. Such objects are created only by the JVMTI function SetBreakpoint, including temporary ones on a thread stack. Either means an agent set a breakpoint on a game method.", "JvmtiBreakpoint es un registro de punto de interrupción. Estos objetos solo los crea la función JVMTI SetBreakpoint, también como temporales en la pila de un hilo. En ambos casos significa que un agente puso un punto de interrupción en un método del juego.")),
        ("JvmtiVMObjectAllocEventCollector", Severity.Info,
            L("Object allocation event collector. IMPORTANT: HotSpot creates it as a local variable in JNI functions (jni_AllocObject and others) UNCONDITIONALLY, so its virtual function table constantly ends up on thread stacks even in a clean game. Verified on a clean Minecraft client — not evidence, given for reference.", "Recolector de eventos de asignación de objetos. IMPORTANTE: HotSpot lo crea como variable local en funciones JNI (jni_AllocObject y otras) INCONDICIONALMENTE, así que su tabla de funciones virtuales acaba constantemente en las pilas de los hilos incluso en una partida limpia. Comprobado en un cliente de Minecraft limpio: no es una prueba, se muestra como referencia.")),
        ("JvmtiDynamicCodeEventCollector", Severity.Info,
            L("Code generation event collector. Created as a local variable inside the VM itself regardless of whether there is an agent — not evidence.", "Recolector de eventos de generación de código. Se crea como variable local dentro de la propia VM haya o no un agente: no es una prueba.")),
    };

    private static void ReportJvmtiObjects(ScanContext ctx, VmStructs vm, VtIndex idx,
        StringBuilder sb)
    {
        sb.AppendLine(L("JVMTI INFRASTRUCTURE OBJECTS (search by the exact vtable address):", "OBJETOS DE INFRAESTRUCTURA JVMTI (búsqueda por la dirección exacta de la vtable):"));
        foreach (var (cls, sev, why) in JvmtiObjectClasses)
        {
            ulong vt = vm.Vtable(cls);
            var list = idx.Get(cls);
            sb.AppendLine(L($"  {cls,-38} vtable=0x{vt:X}  found: ", $"  {cls,-38} vtable=0x{vt:X}  encontrados: ") +
                          (vt == 0 ? L("vtable not exported", "vtable no exportada") : list.Count.ToString()) +
                          (sev == Severity.Info ? L("  (not reported as a finding)", "  (no se reporta como hallazgo)") : ""));
            foreach (ulong a in list.Take(16))
                sb.AppendLine($"      0x{a:X}  {ctx.RegionAt(a)?.TypeString}/" +
                              $"{ctx.RegionAt(a)?.ProtectString}");
            if (vt == 0 || list.Count == 0 || sev == Severity.Info) continue;

            var f = ctx.Report.Report("JVM",
                L($"{list.Count} {cls} objects found in memory", $"Se encontraron {list.Count} objetos {cls} en memoria"), sev, why);
            f.Add(L("virtual function table address", "dirección de la tabla de funciones virtuales"), vt);
            f.Add(L("objects", "objetos"), list.Count.ToString());
            foreach (ulong a in list.Take(24))
                f.Add(L($"object 0x{a:X}", $"objeto 0x{a:X}"), ctx.RegionAt(a)?.ToString() ?? "-");
            var dump = ctx.Target.ReadBytes(list[0], 256);
            if (dump is not null) f.Block(L($"First object 0x{list[0]:X}", $"Primer objeto 0x{list[0]:X}"),
                HexDump.Format(dump, list[0]));
        }
        sb.AppendLine();
    }

    private sealed class EnvRec
    {
        public ulong Address;
        public ulong Functions;
        public uint Magic;
        public uint Version;
        public ulong Next;
        public bool Retransformable;
        public ulong TagMap;
        public ulong LocalStorage;
        public int CallbacksOffset = -1;
        public List<string> Subscriptions = new();
        public List<string> Capabilities = new();
        public List<string> Prohibited = new();
        public ulong[] EventEnable = Array.Empty<ulong>();
        public byte[]? Dump;

        public string MagicName => Magic switch
        {
            JVMTI_MAGIC => L("0x71EE JVMTI_MAGIC (active)", "0x71EE JVMTI_MAGIC (activo)"),
            DISPOSED_MAGIC => L("0xDEFC DISPOSED_MAGIC (DISABLED)", "0xDEFC DISPOSED_MAGIC (DESACTIVADO)"),
            BAD_MAGIC => L("0xDEAD BAD_MAGIC (retired)", "0xDEAD BAD_MAGIC (retirado)"),
            _ => $"0x{Magic:X}",
        };
    }

    private static readonly string[] EventNames =
    {
        "VMInit", "VMDeath", "ThreadStart", "ThreadEnd", "ClassFileLoadHook",
        "ClassLoad", "ClassPrepare", "VMStart", "Exception", "ExceptionCatch",
        "SingleStep", "FramePop", "Breakpoint", "FieldAccess", "FieldModification",
        "MethodEntry", "MethodExit", "NativeMethodBind", "CompiledMethodLoad",
        "CompiledMethodUnload", "DynamicCodeGenerated", "DataDumpRequest", "reserved72",
        "MonitorWait", "MonitorWaited", "MonitorContendedEnter", "MonitorContendedEntered",
        "reserved77", "reserved78", "reserved79", "ResourceExhausted",
        "GarbageCollectionStart", "GarbageCollectionFinish", "ObjectFree", "VMObjectAlloc",
        "reserved85", "SampledObjectAlloc",
    };

    private static readonly string[] CapabilityNames =
    {
        "can_tag_objects", "can_generate_field_modification_events",
        "can_generate_field_access_events", "can_get_bytecodes",
        "can_get_synthetic_attribute", "can_get_owned_monitor_info",
        "can_get_current_contended_monitor", "can_get_monitor_info", "can_pop_frame",
        "can_redefine_classes", "can_signal_thread", "can_get_source_file_name",
        "can_get_line_numbers", "can_get_source_debug_extension",
        "can_access_local_variables", "can_maintain_original_method_order",
        "can_generate_single_step_events", "can_generate_exception_events",
        "can_generate_frame_pop_events", "can_generate_breakpoint_events", "can_suspend",
        "can_redefine_any_class", "can_get_current_thread_cpu_time",
        "can_get_thread_cpu_time", "can_generate_method_entry_events",
        "can_generate_method_exit_events", "can_generate_all_class_hook_events",
        "can_generate_compiled_method_load_events", "can_generate_monitor_events",
        "can_generate_vm_object_alloc_events", "can_generate_native_method_bind_events",
        "can_generate_garbage_collection_events", "can_generate_object_free_events",
        "can_force_early_return", "can_get_owned_monitor_stack_depth_info",
        "can_get_constant_pool", "can_set_native_method_prefix", "can_retransform_classes",
        "can_retransform_any_class", "can_generate_resource_exhaustion_heap_events",
        "can_generate_resource_exhaustion_threads_events", "can_generate_early_vmstart",
        "can_generate_early_class_hook_events", "can_generate_sampled_object_alloc_events",
        "can_support_virtual_threads",
    };

    private static readonly HashSet<string> DangerousCapabilities = new(StringComparer.Ordinal)
    {
        "can_redefine_classes", "can_redefine_any_class", "can_retransform_classes",
        "can_retransform_any_class", "can_generate_breakpoint_events",
        "can_generate_single_step_events", "can_generate_all_class_hook_events",
        "can_generate_early_class_hook_events", "can_set_native_method_prefix",
        "can_generate_native_method_bind_events", "can_pop_frame", "can_force_early_return",
        "can_access_local_variables", "can_suspend", "can_tag_objects",
        "can_generate_field_modification_events", "can_generate_field_access_events",
    };

    private static void WalkJvmtiEnvironments(ScanContext ctx, VmStructs vm, ImageInMemory jvm,
        StringBuilder sb)
    {
        var c = new PageCache(ctx.Target, 8192);
        var rdata = jvm.Pe.Sections
            .Where(s => !s.IsExecutable && s.VirtualSize > 0)
            .Select(s => (Lo: jvm.Base + s.VirtualAddress,
                          Hi: jvm.Base + s.VirtualAddress + s.VirtualSize))
            .ToList();
        bool InJvmData(ulong v) => rdata.Any(x => v >= x.Lo && v < x.Hi);

        bool LooksLikeEnv(ulong a)
        {
            if (a is < 0x10000 or > 0x7FFFFFFFFFFF) return false;
            ulong fn = c.U64(a);
            if (!InJvmData(fn)) return false;
            uint magic = c.U32(a + 8);
            return magic is JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC;
        }

        ulong head = 0, headVar = 0;
        foreach (var sec in jvm.Pe.Sections)
        {
            if (sec.IsExecutable || sec.VirtualSize is 0 or > 32 * 1024 * 1024) continue;
            if (sec.Name is not (".data" or ".rdata")) continue;
            var buf = new byte[sec.VirtualSize];
            ulong va = jvm.Base + sec.VirtualAddress;
            ctx.Target.ReadPartial(va, buf, out _);
            for (int i = 0; i + 8 <= buf.Length && head == 0; i += 8)
            {
                ulong v = BitConverter.ToUInt64(buf, i);
                if (!LooksLikeEnv(v)) continue;
                head = v;
                headVar = va + (ulong)i;
            }
            if (head != 0) break;
        }

        sb.AppendLine(L("JVMTI ENVIRONMENT LIST (JvmtiEnvBase::_head_environment):", "LISTA DE ENTORNOS JVMTI (JvmtiEnvBase::_head_environment):"));
        if (head == 0)
        {
            sb.AppendLine(L("  list head not found — jvm.dll data has no pointer to an environment object.", "  no se encontró la cabeza de la lista: los datos de jvm.dll no tienen ningún puntero a un objeto de entorno."));
            sb.AppendLine();

            FindDetachedEnvironments(ctx, c, jvm, InJvmData, new List<EnvRec>(), sb);

            if (ctx.JvmtiEnvs.Count == 0)
                ctx.Report.Report("JVM",
                    L("The JVMTI environment list is empty: no JvmtiEnvBase object found", "La lista de entornos JVMTI está vacía: no se encontró ningún objeto JvmtiEnvBase"),
                    Severity.Info,
                    L("HotSpot links all agent environments in a singly linked list whose head is a static variable in jvm.dll data. There is no pointer to an environment object there, and a full memory scan did not find such objects either: during the lifetime of the process no agent attached to this virtual machine. This is a negative result, and it is also important for the decision.", "HotSpot enlaza todos los entornos de agentes en una lista simplemente enlazada cuya cabeza es una variable estática en los datos de jvm.dll. Ahí no hay ningún puntero a un objeto de entorno, y una revisión completa de la memoria tampoco encontró estos objetos: durante la vida del proceso ningún agente se conectó a esta máquina virtual. Es un resultado negativo, y también es importante para la decisión."));
            return;
        }

        sb.AppendLine(L($"  head variable: 0x{headVar:X}  →  0x{head:X}", $"  variable cabeza: 0x{headVar:X}  →  0x{head:X}"));

        var envs = new List<EnvRec>();
        ulong p = head;
        var seen = new HashSet<ulong>();
        while (p is >= 0x10000 and <= 0x7FFFFFFFFFFF && envs.Count < 64 && seen.Add(p))
        {
            var e = ReadEnv(ctx, c, p);
            if (e is null) break;
            envs.Add(e);
            p = e.Next;
        }

        sb.AppendLine(L($"  environments in the list: {envs.Count} (active: {envs.Count(x => x.Magic == JVMTI_MAGIC)}, disabled: {envs.Count(x => x.Magic == DISPOSED_MAGIC)}, retired: {envs.Count(x => x.Magic == BAD_MAGIC)})", $"  entornos en la lista: {envs.Count} (activos: {envs.Count(x => x.Magic == JVMTI_MAGIC)}, desactivados: {envs.Count(x => x.Magic == DISPOSED_MAGIC)}, retirados: {envs.Count(x => x.Magic == BAD_MAGIC)})"));
        sb.AppendLine();

        FindDetachedEnvironments(ctx, c, jvm, InJvmData, envs, sb);

        foreach (var e in envs)
        {
            ctx.JvmtiEnvs.Add(e.Address);
            sb.AppendLine($"  jvmtiEnv 0x{e.Address:X}  {e.MagicName}  version=0x{e.Version:X}");
            sb.AppendLine(L($"    function table  : {ctx.Describe(e.Functions)}", $"    tabla de funciones: {ctx.Describe(e.Functions)}"));
            sb.AppendLine(L($"    retransformable : {(e.Retransformable ? "YES (default value)" : "no — AddCapabilities was called")}", $"    retransformable : {(e.Retransformable ? "SÍ (valor por defecto)" : "no: se llamó a AddCapabilities")}"));
            sb.AppendLine($"    JvmtiTagMap*    : 0x{e.TagMap:X}");
            sb.AppendLine(L($"    capabilities    : {(e.Capabilities.Count == 0 ? "-" : string.Join(", ", e.Capabilities))}", $"    capacidades     : {(e.Capabilities.Count == 0 ? "-" : string.Join(", ", e.Capabilities))}"));
            sb.AppendLine(L($"    subscriptions   : {(e.Subscriptions.Count == 0 ? "-" : string.Join(", ", e.Subscriptions.Select(s => s.Split(' ')[0])))}", $"    suscripciones   : {(e.Subscriptions.Count == 0 ? "-" : string.Join(", ", e.Subscriptions.Select(s => s.Split(' ')[0])))}"));
            sb.AppendLine();

            ReportEnv(ctx, e);
        }

    }

    private static void FindDetachedEnvironments(ScanContext ctx, PageCache c, ImageInMemory jvm,
        Func<ulong, bool> inJvmData, List<EnvRec> known, StringBuilder sb)
    {
        var inList = known.Select(e => e.Address).ToHashSet();
        var found = new List<EnvRec>();

        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateData, overlap: 0x20))
        {
            var buf = ch.Data;
            for (int i = 0; i + 0x20 <= ch.Length; i += 8)
            {
                ulong fn = BitConverter.ToUInt64(buf, i);
                if (!inJvmData(fn)) continue;
                uint magic = BitConverter.ToUInt32(buf, i + 8);
                if (magic is not (JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC)) continue;

                ulong addr = ch.Base + (ulong)i;
                if (inList.Contains(addr)) continue;
                if (found.Any(x => x.Address == addr)) continue;
                var e = ReadEnv(ctx, c, addr);
                if (e is null) continue;
                found.Add(e);
                if (found.Count > 64) break;
            }
            if (found.Count > 64) break;
        }

        sb.AppendLine(L($"  private memory scanned: ", $"  memoria privada revisada: ") +
                      MemoryAnalyzer.Human(MemoryScan.TotalReadable(ctx, MemoryScan.PrivateData)) +
                      L(" (no volume limit)", " (sin límite de volumen)"));
        sb.AppendLine(L($"  environments outside the VM list (freed): {found.Count}", $"  entornos fuera de la lista de la VM (liberados): {found.Count}"));
        foreach (var e in found)
            sb.AppendLine(L($"      0x{e.Address:X}  {e.MagicName}  capabilities: {e.Capabilities.Count}, subscriptions: {e.Subscriptions.Count}", $"      0x{e.Address:X}  {e.MagicName}  capacidades: {e.Capabilities.Count}, suscripciones: {e.Subscriptions.Count}"));
        sb.AppendLine();
        if (found.Count == 0) return;

        foreach (var e in found) { ctx.JvmtiEnvs.Add(e.Address); ReportEnv(ctx, e); }

        bool listEmpty = known.Count == 0;
        var f = ctx.Report.Report("JVM",
            L($"Found {found.Count} JVMTI environment objects that are NOT in the virtual machine environment list", $"Se encontraron {found.Count} objetos de entorno JVMTI que NO están en la lista de entornos de la máquina virtual") +
            (listEmpty ? L(" (and the list itself is empty)", " (y la propia lista está vacía)") : ""),
            Severity.Critical,
            L("The virtual machine links all agent environments in a singly linked list whose head is a static variable in jvm.dll data. The object found is not in this list, but it does not stop being an environment object: three independent fields identify it — a pointer to the jvmtiInterface_1_ function table inside jvm.dll, the magic number right after it and the JVMTI version number. ", "La máquina virtual enlaza todos los entornos de agentes en una lista simplemente enlazada cuya cabeza es una variable estática en los datos de jvm.dll. El objeto encontrado no figura en esta lista, pero no deja de ser un objeto de entorno: lo identifican tres campos independientes, un puntero a la tabla de funciones jvmtiInterface_1_ dentro de jvm.dll, el número mágico justo después y el número de versión JVMTI. ") +
            (listEmpty
                ? L("At the same time the list is EMPTY. A healthy VM never has this combination: an environment is either in the list or does not exist at all. An object existing past the registry is either an environment unlinked from the list manually or created bypassing the normal path. This is exactly what hooking the JvmtiEnvBase constructor gives: the environment is created but does not get into the list, and no agent enumeration sees it.", "Al mismo tiempo, la lista está VACÍA. Una VM sana nunca tiene esta combinación: un entorno o está en la lista o no existe. Un objeto que existe al margen del registro es un entorno desenlazado de la lista a mano o creado eludiendo la vía normal. Es exactamente lo que da interceptar el constructor de JvmtiEnvBase: el entorno se crea, pero no entra en la lista, y ninguna enumeración de agentes lo ve.")
                : L("A trace of DisposeEnvironment also looks like this: the environment was taken out of the list, but its memory has not been reused yet.", "Un rastro de DisposeEnvironment también se ve así: el entorno se sacó de la lista, pero su memoria aún no se reutilizó.")));
        foreach (var e in found)
            f.Add(L($"environment 0x{e.Address:X}", $"entorno 0x{e.Address:X}"),
                L($"{e.MagicName}, JVMTI version 0x{e.Version:X}, _next = 0x{e.Next:X}, capabilities {e.Capabilities.Count}, event subscriptions {e.Subscriptions.Count}, region {ctx.RegionAt(e.Address)?.ToString() ?? "-"}", $"{e.MagicName}, versión JVMTI 0x{e.Version:X}, _next = 0x{e.Next:X}, capacidades {e.Capabilities.Count}, suscripciones a eventos {e.Subscriptions.Count}, región {ctx.RegionAt(e.Address)?.ToString() ?? "-"}"));
        _ = jvm;
    }

    private static EnvRec? ReadEnv(ScanContext ctx, PageCache c, ulong addr)
    {
        var dump = ctx.Target.ReadBytes(addr, 0x400);
        if (dump is null) return null;

        var e = new EnvRec
        {
            Address = addr,
            Functions = BitConverter.ToUInt64(dump, 0),
            Magic = BitConverter.ToUInt32(dump, 8),
            Version = BitConverter.ToUInt32(dump, 12),
            Next = BitConverter.ToUInt64(dump, 0x10),
            Retransformable = dump[0x18] != 0,
            LocalStorage = BitConverter.ToUInt64(dump, 0x20),
            Dump = dump,
        };

        var layout = JvmtiEnvLayout.Probe(ctx, dump);
        e.CallbacksOffset = layout?.Callbacks ?? -1;

        if (layout is not null)
        {
            foreach (var (ev, target) in JvmtiEnvLayout.Callbacks(dump, layout))
                e.Subscriptions.Add($"{ev} → {ctx.Describe(target)}");

            e.TagMap = BitConverter.ToUInt64(dump, layout.TagMap);
            e.EventEnable = layout.Masks;
            e.Capabilities = DecodeCapabilities(dump, layout.Capabilities);
            e.Prohibited = DecodeCapabilities(dump, layout.Prohibited);
        }
        return e;
    }

    private static List<string> DecodeCapabilities(byte[] dump, int off)
    {
        var res = new List<string>();
        ulong lo = BitConverter.ToUInt64(dump, off);
        ulong hi = BitConverter.ToUInt64(dump, off + 8);
        if (hi != 0) return res;
        for (int i = 0; i < CapabilityNames.Length; i++)
            if ((lo & (1UL << i)) != 0) res.Add(CapabilityNames[i]);
        return res;
    }

    private static void ReportEnv(ScanContext ctx, EnvRec e)
    {
        Severity sev = e.Magic switch
        {
            DISPOSED_MAGIC => Severity.Critical,
            JVMTI_MAGIC => Severity.Critical,
            BAD_MAGIC => Severity.Critical,
            _ => Severity.High,
        };

        string why = e.Magic == DISPOSED_MAGIC
            ? L("The environment was found by walking the virtual machine\'s own environment LIST and is marked as disabled: an agent was attached to this JVM and called DisposeEnvironment. This is exactly what the «unhook» of a JVMTI cheat looks like. The environment list is an internal HotSpot structure; an agent does not remove its record from it but only changes the magic number, so the capabilities and event subscriptions it requested remain readable.", "El entorno se encontró recorriendo la LISTA de entornos de la propia máquina virtual y está marcado como desactivado: un agente se conectó a esta JVM y llamó a DisposeEnvironment. Así es exactamente el «unhook» de un cheat JVMTI. La lista de entornos es una estructura interna de HotSpot; un agente no elimina de ella su registro, solo cambia el número mágico, así que las capacidades y suscripciones a eventos que solicitó siguen siendo legibles.")
            : e.Magic == JVMTI_MAGIC
                ? L("An active JVMTI environment: an agent is attached to the virtual machine right now. A Minecraft client without agents has none of these environments.", "Un entorno JVMTI activo: ahora mismo hay un agente conectado a la máquina virtual. Un cliente de Minecraft sin agentes no tiene ninguno de estos entornos.")
                : e.Magic == BAD_MAGIC
                    ? L("An environment marked BAD_MAGIC. This is not «corruption»: the value 0xDEAD is written by the virtual machine itself, and the code that does it first checks JVMTI_MAGIC and only then overwrites it (verified by analysing jvm.dll — the function sits next to the environment constructor). So the object was a real working JVMTI environment, and it was retired. The evidence here is the very existence of the object: a client without agents has none of them, in whatever state.", "Un entorno marcado como BAD_MAGIC. No es una «corrupción»: el valor 0xDEAD lo escribe la propia máquina virtual, y el código que lo hace primero comprueba JVMTI_MAGIC y solo después lo sobrescribe (comprobado analizando jvm.dll: la función está junto al constructor del entorno). Por tanto, el objeto fue un entorno JVMTI real en funcionamiento, y se retiró. La prueba aquí es la propia existencia del objeto: un cliente sin agentes no tiene ninguno, en ningún estado.")
                    : L("JVMTI environment with an unknown state mark.", "Entorno JVMTI con una marca de estado desconocida.");

        var f = ctx.Report.Report("JVM",
            L($"JVMTI environment 0x{e.Address:X} in the VM environment list: {e.MagicName}", $"Entorno JVMTI 0x{e.Address:X} en la lista de entornos de la VM: {e.MagicName}"), sev, why);
        f.Add(L("object address", "dirección del objeto"), e.Address);
        f.Add(L("function table", "tabla de funciones"), $"0x{e.Functions:X} → {ctx.Describe(e.Functions)}");
        f.Add(L("JVMTI version", "versión JVMTI"), $"0x{e.Version:X}");
        f.Add("_is_retransformable", JvmtiEnvLayout.DescribeRetransformable(e.Retransformable));
        f.Add("JvmtiTagMap*", e.TagMap == 0 ? L("not created", "no creada") : $"0x{e.TagMap:X}");
        f.Add("_env_local_storage", e.LocalStorage == 0
            ? L("empty", "vacío")
            : L($"0x{e.LocalStorage:X} → {ctx.Describe(e.LocalStorage)} — the agent stored a pointer to its data here (SetEnvironmentLocalStorage)", $"0x{e.LocalStorage:X} → {ctx.Describe(e.LocalStorage)}: el agente guardó aquí un puntero a sus datos (SetEnvironmentLocalStorage)"));
        f.Add(L("callback table offset", "desplazamiento de la tabla de callbacks"), e.CallbacksOffset >= 0
            ? $"+0x{e.CallbacksOffset:X}" : L("not identified", "no identificado"));

        if (e.Capabilities.Count > 0)
        {
            f.Block(L("Requested capabilities (jvmtiCapabilities)", "Capacidades solicitadas (jvmtiCapabilities)"),
                string.Join("\n", e.Capabilities.Select(x =>
                    (DangerousCapabilities.Contains(x) ? "  !! " : "     ") + x)));

            var danger = e.Capabilities.Where(DangerousCapabilities.Contains).ToList();
            if (danger.Count > 0)
            {
                ctx.Report.Report("JVM",
                        L($"JVMTI environment 0x{e.Address:X} has capabilities that allow changing game code and state ({danger.Count})", $"El entorno JVMTI 0x{e.Address:X} dispone de capacidades que permiten cambiar el código y el estado del juego ({danger.Count})"),
                        Severity.Critical,
                        L("jvmtiCapabilities is the set of capabilities the agent EXPLICITLY requested from the virtual machine through AddCapabilities. They can be requested only by an agent, and what was requested stays recorded in the environment object even after the agent detaches. This set shows what exactly the agent intended to do: redefine classes, stop on methods, read and change local variables, replace native method binding.", "jvmtiCapabilities es el conjunto de capacidades que el agente solicitó EXPLÍCITAMENTE a la máquina virtual mediante AddCapabilities. Solo un agente puede solicitarlas, y lo solicitado queda registrado en el objeto de entorno incluso después de que el agente se desconecte. Este conjunto muestra qué pretendía hacer exactamente el agente: redefinir clases, detenerse en métodos, leer y cambiar variables locales, sustituir el enlace de métodos nativos."))
                    .Add(L("environment object", "objeto de entorno"), e.Address)
                    .Add(L("state", "estado"), e.MagicName)
                    .Block(L("Dangerous capabilities", "Capacidades peligrosas"), string.Join("\n", danger.Select(x => "  " + x)))
                    .Block(L("All requested capabilities", "Todas las capacidades solicitadas"),
                        string.Join("\n", e.Capabilities.Select(x => "  " + x)));
            }
        }

        if (e.Subscriptions.Count > 0)
        {
            f.Block(L("Event subscriptions (pointer position = event)", "Suscripciones a eventos (posición del puntero = evento)"),
                string.Join("\n", e.Subscriptions.Select(x => "  " + x)));

            if (e.Subscriptions.Any(s => s.StartsWith("ClassFileLoadHook", StringComparison.Ordinal)))
                ctx.Report.Report("JVM",
                        L($"JVMTI environment 0x{e.Address:X} is subscribed to ClassFileLoadHook", $"El entorno JVMTI 0x{e.Address:X} está suscrito a ClassFileLoadHook"),
                        Severity.Critical,
                        L("ClassFileLoadHook gives the agent the bytecode of every loaded class and accepts a modified one. This is the main mechanism for replacing game code.", "ClassFileLoadHook entrega al agente el bytecode de cada clase que se carga y acepta uno modificado. Es el mecanismo principal para sustituir el código del juego."))
                    .Add(L("environment state", "estado del entorno"), e.MagicName)
                    .Block(L("Subscriptions", "Suscripciones"), string.Join("\n", e.Subscriptions.Select(x => "  " + x)));
        }

        if (e.EventEnable.Length == 3)
        {
            f.Block(L("Event enable bit masks (user / callback / enabled)", "Máscaras de bits de activación de eventos (user / callback / enabled)"),
                $"  _event_user_enabled     = 0x{e.EventEnable[0]:X16}  {Bits(e.EventEnable[0])}\n" +
                $"  _event_callback_enabled = 0x{e.EventEnable[1]:X16}  {Bits(e.EventEnable[1])}\n" +
                $"  _event_enabled          = 0x{e.EventEnable[2]:X16}  {Bits(e.EventEnable[2])}");
        }

        if (e.TagMap is >= 0x10000 and <= 0x7FFFFFFFFFFF)
            ctx.Report.Report("JVM",
                    L($"JVMTI environment 0x{e.Address:X} has an object tag map (JvmtiTagMap 0x{e.TagMap:X})", $"El entorno JVMTI 0x{e.Address:X} tiene una tabla de etiquetas de objetos (JvmtiTagMap 0x{e.TagMap:X})"),
                    Severity.Critical,
                    L("JvmtiTagMap is created on the very first call to SetTag / GetObjectsWithTags / IterateOverHeap. It means the agent tagged and iterated over objects in the Java heap — this is how a cheat looks for player, world and entity objects to get direct access to them.", "JvmtiTagMap se crea en la primera llamada a SetTag / GetObjectsWithTags / IterateOverHeap. Significa que el agente etiquetó y recorrió objetos del heap de Java: así busca un cheat los objetos del jugador, del mundo y de las entidades para acceder a ellos directamente."))
                .Add(L("environment", "entorno"), e.Address)
                .Add("JvmtiTagMap*", e.TagMap);

        if (e.Dump is not null)
            f.Block(L("Environment object (0x400 bytes)", "Objeto de entorno (0x400 bytes)"), HexDump.Format(e.Dump, e.Address));

        if (ctx.Dumper is not null)
        {
            ulong from = e.Address > 0x1000 ? e.Address - 0x1000 : e.Address;
            string? path = ctx.Dumper.DumpRange(from, 0x4000, "jvmtienv-sa",
                L($"JVMTI environment object from the VM list ({e.MagicName})", $"objeto de entorno JVMTI de la lista de la VM ({e.MagicName})"),
                L($"the object itself at 0x{e.Address:X}", $"el propio objeto en 0x{e.Address:X}"));
            if (path is not null) f.Add(L("neighbourhood dump", "volcado del entorno"), path);
        }
    }

    private static string Bits(ulong v)
    {
        if (v == 0) return L("(no enabled events)", "(sin eventos activados)");
        var names = new List<string>();
        for (int i = 0; i < EventNames.Length; i++)
            if ((v & (1UL << i)) != 0) names.Add(EventNames[i]);
        return names.Count == 0 ? L("(bits outside the known range)", "(bits fuera del rango conocido)") : string.Join(",", names);
    }

    private static readonly (string Field, string Why)[] ExportFlags =
    {
        ("_can_hotswap_or_post_breakpoint",
            L("set when some agent requested can_redefine_classes, can_retransform_classes or can_generate_breakpoint_events. While the flag is set, the virtual machine keeps full track of compiled code dependencies and does not apply some optimizations — so the agent\'s work is reflected in the VM itself.", "se activa cuando algún agente solicitó can_redefine_classes, can_retransform_classes o can_generate_breakpoint_events. Mientras la bandera está activa, la máquina virtual lleva un registro completo de las dependencias del código compilado y no aplica algunas optimizaciones: el trabajo del agente se refleja en la propia VM.")),
        ("_can_access_local_variables",
            L("set when can_access_local_variables is requested: the agent intended to read and change local variables in game stack frames.", "se activa al solicitar can_access_local_variables: el agente pretendía leer y cambiar variables locales en los marcos de pila del juego.")),
        ("_can_post_on_exceptions",
            L("set on subscription to exception events.", "se activa al suscribirse a eventos de excepciones.")),
        ("_can_walk_any_space",
            L("set with the capability to walk arbitrary heap regions.", "se activa con la capacidad de recorrer regiones arbitrarias del heap.")),
    };

    private static void ReportJvmtiExportFlags(ScanContext ctx, VmStructs vm, StringBuilder sb)
    {
        sb.AppendLine(L("STATIC JvmtiExport FLAGS (addresses from VMStructs):", "BANDERAS ESTÁTICAS DE JvmtiExport (direcciones de VMStructs):"));
        var on = new List<(string Name, ulong Addr, string Why)>();
        bool any = false;

        foreach (var (field, why) in ExportFlags)
        {
            ulong a = vm.StaticAddr("JvmtiExport", field);
            if (a == 0) { sb.AppendLine(L($"  {field,-40} not described in this build", $"  {field,-40} no descrito en esta compilación")); continue; }
            any = true;
            byte val = ctx.Target.ReadU8(a);
            sb.AppendLine($"  {field,-40} 0x{a:X}  = {val}");
            if (val != 0) on.Add((field, a, why));
        }
        sb.AppendLine();
        if (!any) return;

        if (on.Count == 0)
        {
            ctx.Report.Report("JVM",
                L("Static JvmtiExport flags are off — no agent capabilities are currently requested from the VM", "Las banderas estáticas de JvmtiExport están desactivadas: ahora mismo no se han solicitado capacidades de agente a la VM"),
                Severity.Info,
                L("JvmtiExport keeps the union of capabilities requested by all agent environments. All checked flags are zero: at the time of the check no environment holds the rights to class redefinition, breakpoints and local variable access. The negative result is recorded explicitly because it is needed for the decision.", "JvmtiExport guarda la unión de las capacidades solicitadas por todos los entornos de agentes. Todas las banderas comprobadas son cero: en el momento de la comprobación ningún entorno tiene derechos de redefinición de clases, puntos de interrupción ni acceso a variables locales. El resultado negativo se registra de forma explícita porque es necesario para la decisión."))
                .Add(L("flags checked", "banderas comprobadas"), ExportFlags.Length.ToString());
            return;
        }

        var f = ctx.Report.Report("JVM",
            L($"Static JvmtiExport flags are set in the virtual machine ({on.Count}): ", $"La máquina virtual tiene activas banderas estáticas de JvmtiExport ({on.Count}): ") +
            string.Join(", ", on.Select(x => x.Name)),
            Severity.Critical,
            L("These are global variables inside jvm.dll whose addresses the virtual machine reports itself through the VMStructs table. Only the JVMTI mechanism sets them, when an agent requests the corresponding capabilities. A set flag means agent capabilities were really requested from this VM; in a clean Minecraft client they are all zero.", "Son variables globales dentro de jvm.dll cuyas direcciones informa la propia máquina virtual mediante la tabla VMStructs. Solo las activa el mecanismo JVMTI cuando un agente solicita las capacidades correspondientes. Una bandera activa significa que realmente se solicitaron capacidades de agente a esta VM; en un cliente de Minecraft limpio todas son cero."));
        foreach (var (name, addr, why) in on) f.Add($"{name} (0x{addr:X})", why);
    }

    private static void ReportJvmtiVmStructEntries(ScanContext ctx, VmStructs vm, StringBuilder sb)
    {
        var hits = vm.AllFields
            .Where(x => x.TypeName.Contains("Jvmti", StringComparison.OrdinalIgnoreCase) ||
                        x.FieldName.Contains("jvmti", StringComparison.OrdinalIgnoreCase) ||
                        x.TypeString.Contains("Jvmti", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var types = vm.Types.Values
            .Where(x => x.TypeName.Contains("Jvmti", StringComparison.OrdinalIgnoreCase))
            .ToList();

        sb.AppendLine(L("VMStructs ENTRIES RELATED TO JVMTI:", "ENTRADAS DE VMStructs RELACIONADAS CON JVMTI:"));
        sb.AppendLine(L($"  fields: {hits.Count}, types: {types.Count}", $"  campos: {hits.Count}, tipos: {types.Count}"));
        foreach (var x in hits) sb.AppendLine("    " + x);
        foreach (var x in types) sb.AppendLine(L("    type", "    tipo") + x);
        sb.AppendLine();
    }
}
