using System.Diagnostics;
using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class Scanner
{
    public static ScanReport Run(int pid, Options opt)
    {
        var rep = new ScanReport();
        _opt = opt;
        _skipped.Clear();
        _done = _current = 0;
        CancelRequested = false;
        using var target = ProcessTarget.Open(pid);

        var ctx = new ScanContext { Target = target, Options = opt, Report = rep };
        if (opt.DumpSuspicious && opt.DumpDir is not null)
            ctx.Dumper = new RegionDumper(target, opt.DumpDir, opt.MaxDumpBytes);

        Step(L("Process information", "Información del proceso"), () => ProcessInfoAnalyzer.Run(ctx), rep);
        Step(L("Memory map", "Mapa de memoria"), () => { ctx.Regions = MemoryMap.Enumerate(target); }, rep);
        Step(L("Loader lists", "Listas del cargador"), () =>
        {
            ctx.Loader = LoaderModules.Enumerate(target);
            foreach (var e in ctx.Loader.Errors) rep.Errors.Add(L("Loader: ", "Cargador: ") + e);
        }, rep);
        Quiet(L("Modules (service)", "Módulos (servicio)"), () => ModuleAnalyzer.Run(ctx), rep);
        Quiet(L("Threads (service)", "Hilos (servicio)"), () => ThreadAnalyzer.Run(ctx), rep);

        List<VmTable> tables = new();
        Step(L("JNI/JVMTI tables", "Tablas JNI/JVMTI"), () =>
        {
            tables = JvmAnalyzer.FindVmTables(ctx);
            ctx.VmTables = tables;
        }, rep);

        var raw = new List<RawPattern>();
        Step(L("HotSpot structure layout (live VMStructs)", "Disposición de estructuras HotSpot (VMStructs en vivo)"),
            () => raw.AddRange(SaLiveAnalyzer.Prepare(ctx)), rep);
        Step(L("VM event logs: search preparation", "Registros de eventos de la VM: preparación de la búsqueda"),
            () => raw.AddRange(VmEventLogAnalyzer.Prepare(ctx)), rep);

        foreach (var tbl in tables)
        {
            var rp = new RawPattern
            {
                Name = $"{tbl.Kind} @ 0x{tbl.Address:X}",
                Bytes = BitConverter.GetBytes(tbl.Address),
                MaxHits = 512,
            };
            tbl.RefPattern = rp;
            raw.Add(rp);
        }

        var sweep = new SweepResult();
        if (opt.FullStringScan)
        {
            Step(L("Full memory scan", "Escaneo completo de memoria"), () =>
            {
                var sigs = Signatures.Load(null);
                sweep = MemorySweep.Run(ctx, sigs, raw, Progress);
                Console.Error.Write("\r".PadRight(60) + "\r");
            }, rep);
        }
        Step(L("Game archive index", "Índice de archivos del juego"), () => ctx.Jars = AgentInfra.BuildJarIndex(ctx, sweep), rep);

        Step(L("Agent and JVMTI signatures in memory", "Firmas de agentes y JVMTI en memoria"),
            () => AgentInfra.ReportSweep(ctx, sweep), rep);
        Step(L("JVM / JVMTI: command line, agent modules, threads, tables", "JVM / JVMTI: línea de comandos, módulos de agentes, hilos, tablas"),
            () => JvmAnalyzer.Run(ctx, sweep, tables), rep);
        Step(L("JVM: JavaVM table and redefined classes", "JVM: tabla JavaVM y clases redefinidas"),
            () => JvmExtraAnalyzer.Run(ctx, sweep), rep);
        Step(L("JVM: residual agent state", "JVM: estado residual de agentes"),
            () => JvmResidualAnalyzer.Run(ctx, tables, sweep), rep);
        Step(L("HotSpot black box: virtual machine event logs", "Caja negra de HotSpot: registros de eventos de la máquina virtual"),
            () => VmEventLogAnalyzer.Run(ctx, sweep), rep);
        Step(L("Live SA: metaspace, loaders, JVMTI", "SA en vivo: metaspace, cargadores, JVMTI"),
            () => SaLiveAnalyzer.Run(ctx, sweep), rep);
        Step(L("Java class field layout (reading objects by field names)", "Disposición de campos de clases Java (lectura de objetos por nombre de campo)"),
            () => ctx.Java = JavaMeta.Create(ctx), rep);
        Step(L("Game name style (service)", "Estilo de nombres del juego (servicio)"), () => AgentInfra.DetectRemap(ctx, sweep), rep);
        Step(L("Virtual machine flags: values and origin", "Banderas de la máquina virtual: valores y origen"),
            () => VmFlagsAnalyzer.Run(ctx), rep);
        Step(L("Attach points: HotSpot agent lists and the attach mechanism", "Puntos de conexión: listas de agentes de HotSpot y mecanismo attach"),
            () => JvmtiAgentListForensicsAnalyzer.Run(ctx), rep);
        Step(L("JVMTI agent provenance (recovery from residues)", "Procedencia del agente JVMTI (recuperación a partir de restos)"),
            () => JvmtiAgentProvenanceAnalyzer.Run(ctx), rep);
        Step(L("JVMTI environments by magic number (independent search)", "Entornos JVMTI por número mágico (búsqueda independiente)"),
            () => JvmtiMagicScanAnalyzer.Run(ctx), rep);
        Quiet(L("Code cache: structural walk (service)", "Caché de código: recorrido estructural (servicio)"),
            () => CodeCacheWalkAnalyzer.Run(ctx), rep);
        Step(L("Java heap: object index", "Heap de Java: índice de objetos"), () =>
        {
            var idx = JavaHeapIndex.Get(ctx);
            if (idx is not null && idx.Diagnostics.Count > 0)
                rep.Errors.Add(L("Java heap: ", "Heap de Java: ") + string.Join("; ", idx.Diagnostics));
        }, rep);
        Step(L("Safepoint operations", "Operaciones en safepoints"),
            () => SafepointProfileAnalyzer.Run(ctx), rep);
        Step(L("Java agent mechanism: Instrumentation and class transformers", "Mecanismo de agentes Java: Instrumentation y transformadores de clases"),
            () => AgentInstrumentationAnalyzer.Run(ctx), rep);
        Step(L("Classes in privileged loaders", "Clases en cargadores privilegiados"),
            () => BootLoaderIntrusionAnalyzer.Run(ctx), rep);
        Step(L("Java runtime: properties, opened packages, native libraries", "Entorno de ejecución Java: propiedades, paquetes abiertos, bibliotecas nativas"),
            () => JavaRuntimeStateAnalyzer.Run(ctx), rep);
        Step(L("VM performance counters (hsperfdata)", "Contadores de rendimiento de la VM (hsperfdata)"),
            () => PerfDataAnalyzer.Run(ctx), rep);
        Step(L("Redefinition counters in class mirrors (service)", "Contadores de redefinición en espejos de clase (servicio)"),
            () => AgentInfra.CollectMirrorCounters(ctx), rep);
        Step(L("Class redefinition consequences: source reconciliation", "Consecuencias de la redefinición de clases: conciliación de fuentes"),
            () => RedefinitionResidualGraphAnalyzer.Run(ctx), rep);

        if (_skipped.Count > 0)
        {
            rep.AddMeta(L("INCOMPLETE RUN", "EJECUCIÓN INCOMPLETA"),
                L($"skipped by step selection: {_skipped.Count} (--only/--skip) — do not compare with full runs", $"omitidos por selección de pasos: {_skipped.Count} (--only/--skip); no compare con ejecuciones completas"));
            var sb = new StringBuilder();
            sb.AppendLine(L("RUN PERFORMED WITH STEP SELECTION — REPORT INCOMPLETE", "EJECUCIÓN CON SELECCIÓN DE PASOS: INFORME INCOMPLETO"));
            sb.AppendLine();
            if (opt.OnlySteps.Count > 0)
                sb.AppendLine("  --only: " + string.Join(", ", opt.OnlySteps));
            if (opt.SkipSteps.Count > 0)
                sb.AppendLine("  --skip: " + string.Join(", ", opt.SkipSteps));
            sb.AppendLine();
            foreach (string s in _skipped) sb.AppendLine("    · " + s);
            rep.Section(L("STEP SELECTION: WHAT WAS NOT RUN", "SELECCIÓN DE PASOS: LO QUE NO SE EJECUTÓ"), sb.ToString());
        }

        Report(TotalWeight, L("Done", "Hecho"));
        return rep;
    }

    private static void Progress(string s)
    {
        Console.Error.Write($"\r  {En(s)}   ");
        var m = System.Text.RegularExpressions.Regex.Match(s, @"(\d+)%");
        if (m.Success && int.TryParse(m.Groups[1].Value, out int pct))
            Report(_done + _current * Math.Clamp(pct, 0, 100) / 100.0, s);
    }

    public static event Action<double, string>? ProgressChanged;

    private const int StepCount = 31;

    private static readonly (string Prefix, double Weight)[] Weights =
    {
        ("Full memory scan", 17), ("Live SA", 12), ("JVMTI agent provenance", 12),
        ("Game archive index", 9), ("Attach points", 9), ("Java heap: object", 2.5),
        ("Modules", 1.5), ("JVMTI environments by magic", 1.3), ("JVM: residual", 1),
    };
    private const double DefaultWeight = 0.2;
    private static readonly double TotalWeight =
        Weights.Sum(w => w.Weight) + (StepCount - Weights.Length) * DefaultWeight;
    private static double _done, _current;

    private static double WeightOf(string name)
    {
        foreach (var (p, w) in Weights)
            if (name.StartsWith(p, StringComparison.Ordinal)) return w;
        return DefaultWeight;
    }

    private static void Report(double doneWeight, string text) =>
        ProgressChanged?.Invoke(Math.Clamp(doneWeight / TotalWeight, 0, 1), text);

    private static Options? _opt;
    private static readonly List<string> _skipped = new();

    private static bool Selected(string name)
    {
        if (_opt is null) return true;
        foreach (string s in _opt.SkipSteps)
            if (name.Contains(s, StringComparison.OrdinalIgnoreCase)) return false;
        if (_opt.OnlySteps.Count == 0) return true;
        foreach (string s in _opt.OnlySteps)
            if (name.Contains(s, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static void Quiet(string name, Action a, ScanReport rep)
    {
        int findings = rep.Findings.Count, sections = rep.Sections.Count;
        Step(name, a, rep);
        if (rep.Findings.Count > findings)
            rep.Findings.RemoveRange(findings, rep.Findings.Count - findings);
        if (rep.Sections.Count > sections)
            rep.Sections.RemoveRange(sections, rep.Sections.Count - sections);
    }

    public static volatile bool CancelRequested;

    private static void Step(string name, Action a, ScanReport rep)
    {
        if (CancelRequested) throw new OperationCanceledException("Scan cancelled");
        string plain = En(name);

        if (!Selected(plain))
        {
            _skipped.Add(name);
            return;
        }

        var sw = Stopwatch.StartNew();
        Console.Error.Write($"  [..] {plain}");
        _current = WeightOf(plain);
        Report(_done, name);
        try
        {
            a();
            Console.Error.WriteLine($"\r  [ok] {plain} ({sw.ElapsedMilliseconds} ms)".PadRight(70));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"\r  [!!] {plain}: {ex.GetType().Name}: {ex.Message}".PadRight(70));
            rep.Errors.Add($"{name}: {ex}");
        }
        _done += _current;
        _current = 0;
    }
}
