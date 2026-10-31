using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class RedefinitionResidualGraphAnalyzer
{
    private sealed class Ev
    {
        public string Ring = "";
        public double Ts;
        public ulong Thread;
        public string Text = "";
        public string? ClassName;
    }

    private sealed class Episode
    {
        public Ev Redefine = null!;
        public List<Ev> Nearby = new();
        public List<(ulong Method, uint Flags, string Klass)> OldMethods = new();
        public List<CodeBlobInfo> DeadBlobs = new();
    }

    private const double WindowSeconds = 2.0;

    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        Preamble(sb);

        var vm = ctx.Vm;
        var events = ctx.VmEvents
            .Select(e => new Ev
            {
                Ring = e.Ring, Ts = e.Seconds, Thread = e.Thread, Text = e.Text,
                ClassName = ExtractClassName(e.Text),
            })
            .OrderBy(e => e.Ts)
            .ToList();

        var oldMethods = CollectOldMethods(ctx);
        var invalid = ctx.CodeBlobs.Where(b => b.IsNmethod && b.State != 0).ToList();
        var deadMethodBlobs = CollectDeadMethodBlobs(ctx);

        RenderSources(ctx, events, oldMethods, invalid, deadMethodBlobs, sb);

        var episodes = BuildEpisodes(ctx, events, oldMethods, deadMethodBlobs);
        RenderEpisodes(ctx, episodes, sb);

        var bands = InvalidationBands(ctx, sb);

        ReportDisagreement(ctx, events, oldMethods, deadMethodBlobs, sb);
        ReportMirrorCounters(ctx, events, sb);
        ReportEpisodes(ctx, episodes);
        bool redefinitionSeen = events.Any(e => e.Ring == "redefine") ||
                                oldMethods.Count > 0 || ctx.RedefinedClassMirrors.Count > 0;
        ReportBands(ctx, bands, redefinitionSeen);
        ReportDeoptStorm(ctx, events, sb);
        ReportOrphanDeoptState(ctx, invalid, sb);

        ctx.Report.Section(L("CLASS REDEFINITION CONSEQUENCES: SOURCE RECONCILIATION", "CONSECUENCIAS DE LA REDEFINICIÓN DE CLASES: CONCILIACIÓN DE FUENTES"),
            sb.ToString());
    }

    private static void Preamble(StringBuilder sb)
    {
        sb.AppendLine(L("GRAPH OF CLASS REDEFINITION AND DEOPTIMIZATION CONSEQUENCES", "GRAFO DE CONSECUENCIAS DE LA REDEFINICIÓN DE CLASES Y LA DESOPTIMIZACIÓN"));
        sb.AppendLine();
        sb.AppendLine(L("When redefining a class, the virtual machine leaves four traces in", "Al redefinir una clase, la máquina virtual deja cuatro rastros en"));
        sb.AppendLine(L("four different places, kept by different subsystems:", "cuatro lugares distintos, que mantienen subsistemas diferentes:"));
        sb.AppendLine();
        sb.AppendLine(L("    1) a text entry in the «Classes redefined» ring log;", "    1) una entrada de texto en el registro circular «Classes redefined»;"));
        sb.AppendLine(L("    2) IS_OLD / IS_OBSOLETE flags on Method objects of the old version;", "    2) banderas IS_OLD / IS_OBSOLETE en los objetos Method de la versión antigua;"));
        sb.AppendLine(L("    3) switching all nmethods of the class to the «invalid» state;", "    3) el paso de todos los nmethod de la clase al estado «no válido»;"));
        sb.AppendLine(L("    4) evol_method dependencies in compiled code.", "    4) dependencias evol_method en el código compilado."));
        sb.AppendLine();
        sb.AppendLine(L("To hide a redefinition, all four must be cleaned, and consistently.", "Para ocultar una redefinición hay que limpiar los cuatro, y de forma coherente."));
        sb.AppendLine(L("So what is searched for here is not traces but a MISMATCH between them: a place where", "Por eso aquí no se buscan rastros, sino una DISCREPANCIA entre ellos: un lugar donde"));
        sb.AppendLine(L("one source reports an event and another is silent about it.", "una fuente informa de un evento y otra calla."));
        sb.AppendLine();
    }

    private static List<(ulong Method, uint Flags, string Klass)> CollectOldMethods(
        ScanContext ctx)
    {
        var res = new List<(ulong, uint, string)>();
        var vm = ctx.Vm;
        if (vm is null || !vm.Valid || ctx.LiveKlasses.Count == 0) return res;

        int offMethods = vm.Off("InstanceKlass", "_methods");
        int offAcc = vm.Off("Method", "_access_flags");
        if (offMethods < 0 || offAcc < 0) return res;

        var c = new PageCache(ctx.Target);
        foreach (var kv in ctx.LiveKlasses)
        {
            ulong arr = c.U64(kv.Key + (ulong)offMethods);
            if (arr is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
            int len = (int)c.U32(arr);
            if (len is <= 0 or > 100_000) continue;

            for (int i = 0; i < len; i++)
            {
                ulong m = c.U64(arr + 8 + (ulong)i * 8);
                if (m is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                uint acc = c.U32(m + (ulong)offAcc);
                if ((acc & 0x00070000) == 0) continue;
                res.Add((m, acc, kv.Value));
                if (res.Count > 20000) return res;
            }
        }
        return res;
    }

    private static List<CodeBlobInfo> CollectDeadMethodBlobs(ScanContext ctx)
    {
        if (ctx.LiveMethods.Count == 0) return new List<CodeBlobInfo>();
        var dead = ctx.CodeBlobs
            .Where(b => b.IsNmethod && b.Method != 0 && !ctx.LiveMethods.Contains(b.Method))
            .ToList();
        if (dead.Count == 0 || ctx.Vm is not { Valid: true } vm) return dead;

        var holders = SaLiveAnalyzer.ResolveMethodHolders(new PageCache(ctx.Target), vm,
            dead.Select(b => b.Method).Distinct());
        return dead
            .Where(b => !holders.TryGetValue(b.Method, out var h) ||
                        !SaLiveAnalyzer.IsRuntimeMethodHolder(h))
            .ToList();
    }

    private static void RenderSources(ScanContext ctx, List<Ev> events,
        List<(ulong Method, uint Flags, string Klass)> oldMethods,
        List<CodeBlobInfo> invalid, List<CodeBlobInfo> deadBlobs, StringBuilder sb)
    {
        int redef = events.Count(e => e.Ring == "redefine");
        int deopt = events.Count(e => e.Ring == "deopt");
        int flush = events.Count(e => e.Ring == "nmethodflushes");
        int unload = events.Count(e => e.Ring == "unload");

        sb.AppendLine(L("WHAT EACH SOURCE SAYS", "QUÉ DICE CADA FUENTE"));
        sb.AppendLine(L($"  redefinition log (redefine)        : {redef} entries", $"  registro de redefiniciones (redefine)  : {redef} entradas") +
                      RingNote(ctx, "redefine"));
        sb.AppendLine(L($"  deoptimization log (deopt)         : {deopt} entries", $"  registro de desoptimizaciones (deopt)  : {deopt} entradas") +
                      RingNote(ctx, "deopt"));
        sb.AppendLine(L($"  method flush log (nmethodflushes)  : {flush} entries", $"  registro de descartes (nmethodflushes) : {flush} entradas") +
                      RingNote(ctx, "nmethodflushes"));
        sb.AppendLine(L($"  class unload log (unload)          : {unload} entries", $"  registro de descarga de clases (unload): {unload} entradas") +
                      RingNote(ctx, "unload"));
        sb.AppendLine(L($"  methods with redefinition flags    : {oldMethods.Count}", $"  métodos con banderas de redefinición   : {oldMethods.Count}"));
        sb.AppendLine(L($"  invalid nmethods in the cache      : {invalid.Count} of {ctx.CodeBlobs.Count(b => b.IsNmethod)}", $"  nmethod no válidos en la caché         : {invalid.Count} de {ctx.CodeBlobs.Count(b => b.IsNmethod)}"));
        sb.AppendLine(L($"  nmethods with an unreachable Method: {deadBlobs.Count}", $"  nmethod con Method inalcanzable        : {deadBlobs.Count}"));
        sb.AppendLine(L($"  class mirror redefinition count > 0: {ctx.RedefinedClassMirrors.Count} classes", $"  contador de redefiniciones del espejo > 0: {ctx.RedefinedClassMirrors.Count} clases") +
                      (ctx.RedefinedClassMirrors.Count > 0
                          ? L($", redefinitions in total {ctx.RedefinedClassMirrors.Sum(x => (long)x.Count)}", $", redefiniciones en total {ctx.RedefinedClassMirrors.Sum(x => (long)x.Count)}")
                          : ""));
        sb.AppendLine();

        if (oldMethods.Count > 0)
        {
            sb.AppendLine(L("  Classes that have methods with redefinition flags:", "  Clases que tienen métodos con banderas de redefinición:"));
            foreach (var g in oldMethods.GroupBy(x => x.Klass)
                                        .OrderByDescending(g => g.Count()).Take(40))
                sb.AppendLine($"      {g.Count(),5}  {g.Key}");
            sb.AppendLine();
        }
    }

    private static void ReportMirrorCounters(ScanContext ctx, List<Ev> events, StringBuilder sb)
    {
        var counters = ctx.RedefinedClassMirrors;
        if (counters.Count == 0) return;

        var logged = events.Where(e => e.Ring == "redefine" && e.ClassName is not null)
            .Select(e => e.ClassName!.Replace('.', '/'))
            .ToHashSet(StringComparer.Ordinal);
        var lost = counters.Where(c => !logged.Contains(c.Name.Replace('.', '/'))).ToList();

        sb.AppendLine(L("CLASS MIRROR REDEFINITION COUNTERS VERSUS THE LOG", "CONTADORES DE REDEFINICIÓN DE LOS ESPEJOS DE CLASE FRENTE AL REGISTRO"));
        sb.AppendLine(L($"  classes with counter > 0    : {counters.Count}", $"  clases con contador > 0     : {counters.Count}"));
        sb.AppendLine(L($"  of them present in the log  : {counters.Count - lost.Count}", $"  de ellas, en el registro    : {counters.Count - lost.Count}"));
        sb.AppendLine(L($"  LOST by the log             : {lost.Count}", $"  PERDIDAS por el registro    : {lost.Count}"));
        foreach (var c in counters.OrderByDescending(x => x.Count))
            sb.AppendLine($"      {c.Count,4} ×  {c.Name}" +
                          (logged.Contains(c.Name.Replace('.', '/')) ? "" : L("   [not in the log]", "   [no está en el registro]")));
        sb.AppendLine();

        long total = counters.Sum(x => (long)x.Count);
        var f = ctx.Report.Report("JVM",
            L($"Mirrors of {counters.Count} classes hold a JVMTI redefinition counter: {total} redefinitions in total", $"Los espejos de {counters.Count} clases guardan un contador de redefiniciones mediante JVMTI: {total} redefiniciones en total") + (lost.Count > 0 ? L($", of which {lost.Count} classes the VM log has already lost", $", de las cuales el registro de la VM ya perdió {lost.Count} clases") : ""),
            Severity.Critical,
            L("The virtual machine increments the classRedefinedCount field of the java.lang.Class object on every RedefineClasses and never resets it. Unlike the twenty-entry ring log, this is an exact per-class count for the whole lifetime of the process. On-the-fly class redefinition is possible only through a JVMTI agent; a normal client redefines no classes, and on a clean target the counter is zero for all of them.", "La máquina virtual incrementa el campo classRedefinedCount del objeto java.lang.Class en cada RedefineClasses y nunca lo reinicia. A diferencia del registro circular de veinte entradas, es un recuento exacto por clase durante toda la vida del proceso. La redefinición de clases en caliente solo es posible mediante un agente JVMTI; un cliente normal no redefine ninguna clase y, en un objetivo limpio, el contador es cero en todas."));
        foreach (var c in counters.OrderByDescending(x => x.Count).Take(40))
            f.Add(c.Name, L($"redefinitions {c.Count}", $"redefiniciones {c.Count}") +
                          (logged.Contains(c.Name.Replace('.', '/')) ? "" : L(" — not in the log", ": no está en el registro")));
    }

    private static string RingNote(ScanContext ctx, string handle)
    {
        if (!ctx.VmEventRings.TryGetValue(handle, out var r)) return L("  [log not found]", "  [registro no encontrado]");
        return r.Count >= r.Length
            ? L($"  [ring completely full: {r.Count}/{r.Length}, old entries were pushed out]", $"  [anillo completamente lleno: {r.Count}/{r.Length}, las entradas antiguas se desplazaron]")
            : L($"  [ring {r.Count}/{r.Length}, nothing pushed out]", $"  [anillo {r.Count}/{r.Length}, no hubo desplazamiento]");
    }

    private static List<Episode> BuildEpisodes(ScanContext ctx, List<Ev> events,
        List<(ulong Method, uint Flags, string Klass)> oldMethods,
        List<CodeBlobInfo> deadBlobs)
    {
        var res = new List<Episode>();
        foreach (var r in events.Where(e => e.Ring == "redefine"))
        {
            var ep = new Episode { Redefine = r };
            foreach (var e in events)
            {
                if (ReferenceEquals(e, r)) continue;
                if (Math.Abs(e.Ts - r.Ts) > WindowSeconds) continue;
                ep.Nearby.Add(e);
            }
            if (r.ClassName is not null)
            {
                string norm = r.ClassName.Replace('.', '/');
                ep.OldMethods = oldMethods
                    .Where(m => m.Klass.Replace('.', '/')
                        .Equals(norm, StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }
            res.Add(ep);
        }
        return res;
    }

    private static void RenderEpisodes(ScanContext ctx, List<Episode> episodes, StringBuilder sb)
    {
        sb.AppendLine(L("REDEFINITION EPISODES (the event and everything that happened near it in time)", "EPISODIOS DE REDEFINICIÓN (el evento y todo lo que ocurrió cerca en el tiempo)"));
        if (episodes.Count == 0)
        {
            sb.AppendLine(L("  The log has no class redefinition entries.", "  El registro no tiene entradas de redefinición de clases."));
            sb.AppendLine();
            return;
        }

        DateTime start = ctx.Target.StartTimeUtc;
        foreach (var ep in episodes)
        {
            string wall = start == default ? ""
                : "  (" + start.AddSeconds(ep.Redefine.Ts).ToString("HH:mm:ss.fff") + " UTC)";
            sb.AppendLine(L($"=== +{ep.Redefine.Ts:F3} s{wall}  thread 0x{ep.Redefine.Thread:X}", $"=== +{ep.Redefine.Ts:F3} s{wall}  hilo 0x{ep.Redefine.Thread:X}"));
            sb.AppendLine($"    {ep.Redefine.Text}");
            sb.AppendLine(L($"    methods of this class with redefinition flags: {ep.OldMethods.Count}", $"    métodos de esta clase con banderas de redefinición: {ep.OldMethods.Count}"));
            if (ep.Nearby.Count > 0)
            {
                sb.AppendLine(L($"    nearby in time (±{WindowSeconds:F0} s): {ep.Nearby.Count} events", $"    cerca en el tiempo (±{WindowSeconds:F0} s): {ep.Nearby.Count} eventos"));
                foreach (var e in ep.Nearby.OrderBy(x => x.Ts).Take(20))
                    sb.AppendLine(L($"        +{e.Ts:F3} s  [{e.Ring}]  {Cut(e.Text, 96)}", $"        +{e.Ts:F3} s  [{e.Ring}]  {Cut(e.Text, 96)}"));
                if (ep.Nearby.Count > 20)
                    sb.AppendLine(L($"        ... {ep.Nearby.Count - 20} more", $"        ... {ep.Nearby.Count - 20} más"));
            }
            else
            {
                sb.AppendLine(L("    NOTHING happened nearby in time — no deoptimizations,", "    NADA ocurrió cerca en el tiempo: ni desoptimizaciones,"));
                sb.AppendLine(L("    no compiled method flushes, no class loading.", "    ni descartes de métodos compilados, ni carga de clases."));
            }
            sb.AppendLine();
        }
    }

    private sealed class Band
    {
        public int From, To, Count;
        public List<CodeBlobInfo> Blobs = new();
    }

    private static List<Band> InvalidationBands(ScanContext ctx, StringBuilder sb)
    {
        sb.AppendLine(L("INVALIDATION BANDS IN COMPILER NUMBERING", "BANDAS DE INVALIDACIÓN EN LA NUMERACIÓN DEL COMPILADOR"));

        var nm = ctx.CodeBlobs.Where(b => b.IsNmethod).ToList();
        if (nm.Count == 0)
        {
            sb.AppendLine(L("  Code cache layout not obtained — the check is not applicable.", "  No se obtuvo la disposición de la caché de código: la comprobación no es aplicable."));
            sb.AppendLine();
            return new List<Band>();
        }

        var ordered = nm.OrderBy(b => b.Lo).ToList();
        var bands = new List<Band>();
        int i = 0;
        while (i < ordered.Count)
        {
            if (ordered[i].State == 0) { i++; continue; }
            int j = i;
            while (j + 1 < ordered.Count && ordered[j + 1].State != 0) j++;
            int count = j - i + 1;
            if (count >= 4)
            {
                var b = new Band { From = i, To = j, Count = count };
                b.Blobs.AddRange(ordered.Skip(i).Take(count));
                bands.Add(b);
            }
            i = j + 1;
        }

        int invalid = nm.Count(b => b.State != 0);
        sb.AppendLine(L($"  compiled methods in the cache: {nm.Count}, invalid among them: {invalid}", $"  métodos compilados en la caché: {nm.Count}, de ellos no válidos: {invalid}"));
        sb.AppendLine(L($"  contiguous bands (4 or more in a row): {bands.Count}", $"  bandas contiguas (4 o más seguidos): {bands.Count}"));
        foreach (var b in bands.OrderByDescending(x => x.Count).Take(20))
            sb.AppendLine(L($"      {b.Count,5} in a row, addresses 0x{b.Blobs[0].Lo:X}…0x{b.Blobs[^1].Hi:X}", $"      {b.Count,5} seguidos, direcciones 0x{b.Blobs[0].Lo:X}…0x{b.Blobs[^1].Hi:X}"));
        sb.AppendLine();
        return bands;
    }

    private static void ReportDisagreement(ScanContext ctx, List<Ev> events,
        List<(ulong Method, uint Flags, string Klass)> oldMethods,
        List<CodeBlobInfo> deadBlobs, StringBuilder sb)
    {
        int redef = events.Count(e => e.Ring == "redefine");
        bool ringFound = ctx.VmEventRings.ContainsKey("redefine");
        bool ringFull = ringFound && ctx.VmEventRings["redefine"].Count >=
                        ctx.VmEventRings["redefine"].Length;

        sb.AppendLine(L("SOURCE RECONCILIATION", "CONCILIACIÓN DE FUENTES"));

        if (oldMethods.Count > 0 && redef == 0)
        {
            sb.AppendLine(L("  MISMATCH: there are methods with redefinition flags, but there are no entries", "  DISCREPANCIA: hay métodos con banderas de redefinición, pero no hay entradas"));
            sb.AppendLine(L("  in the redefinition log.", "  en el registro de redefiniciones."));
            ctx.Report.Report("JVM",
                    L($"There are methods with redefinition flags ({oldMethods.Count}), but the redefinition log is empty", $"Hay métodos con banderas de redefinición ({oldMethods.Count}), pero el registro de redefiniciones está vacío"),
                    ringFound && !ringFull ? Severity.Critical : Severity.High,
                    L("The IS_OLD and IS_OBSOLETE flags are set ONLY by class redefinition (RedefineClasses / RetransformClasses), and the same operation must leave a text entry in the «Classes redefined» ring log. There is no entry but there are flags — so these two records of one event diverged. The redefinition ring does not overflow in a quiet game: the game has no reason to redefine classes, and entries in it are not pushed out. ", "Las banderas IS_OLD e IS_OBSOLETE las pone SOLO la redefinición de clases (RedefineClasses / RetransformClasses), y la misma operación debe dejar una entrada de texto en el registro circular «Classes redefined». No hay entrada pero sí banderas: estos dos registros de un mismo evento divergieron. El anillo de redefiniciones no se desborda en una partida tranquila: el juego no tiene motivos para redefinir clases y sus entradas no se desplazan. ") +
                    (ringFound && !ringFull
                        ? L("The ring was found and is NOT completely full — so nothing was pushed out and the entry did not vanish by itself: the log was wiped.", "El anillo se encontró y NO está completamente lleno: no hubo desplazamiento y la entrada no desapareció sola: el registro se borró.")
                        : L("The ring is either not found or completely full, so natural displacement cannot be ruled out — but it is worth checking manually against the other logs.", "El anillo no se encontró o está completamente lleno, así que no puede descartarse un desplazamiento natural, pero conviene comprobarlo a mano con los demás registros.")))
                .Add(L("methods with flags", "métodos con banderas"), oldMethods.Count.ToString())
                .Add(L("classes affected", "clases afectadas"), oldMethods.Select(m => m.Klass).Distinct().Count()
                    .ToString())
                .Add(L("ring state", "estado del anillo"), RingNote(ctx, "redefine").Trim())
                .Add(L("classes", "clases"), string.Join(", ",
                    oldMethods.Select(m => m.Klass).Distinct().Take(12)));
        }

        if (redef > 0 && oldMethods.Count == 0)
        {
            sb.AppendLine(L("  MISMATCH: the log reports a redefinition, but not a single", "  DISCREPANCIA: el registro informa de una redefinición, pero no queda"));
            sb.AppendLine(L("  method with flags remains.", "  ningún método con banderas."));
            ctx.Report.Report("JVM",
                    L($"The log reports {redef} class redefinitions, but there is not a single method with redefinition flags in the metaspace", $"El registro informa de {redef} redefiniciones de clases, pero no hay ningún método con banderas de redefinición en el metaspace"),
                    Severity.High,
                    L("A class redefinition leaves the old version of its methods in the metaspace with the IS_OLD and IS_OBSOLETE flags — the virtual machine itself needs them so that stack frames started on the old code can finish. The complete absence of such methods with a non-empty log means the old versions have already been collected — or the flags were removed. The first is possible and natural; the second is not. The other sources help to tell them apart: if nmethods with unreachable Methods hang in the cache at the same time, the old versions did exist.", "Una redefinición de clase deja la versión antigua de sus métodos en el metaspace con las banderas IS_OLD e IS_OBSOLETE: la propia máquina virtual las necesita para que terminen los marcos de pila iniciados con el código antiguo. La ausencia total de esos métodos con un registro no vacío significa que las versiones antiguas ya se recogieron, o que se quitaron las banderas. Lo primero es posible y natural; lo segundo no. Las demás fuentes ayudan a distinguirlo: si a la vez hay en la caché nmethod con Method inalcanzables, las versiones antiguas sí existieron."))
                .Add(L("redefinition entries", "entradas de redefinición"), redef.ToString())
                .Add(L("nmethods with an unreachable Method", "nmethod con Method inalcanzable"), deadBlobs.Count.ToString())
                .Add(L("classes from the log", "clases del registro"), string.Join(", ", events
                    .Where(e => e.Ring == "redefine" && e.ClassName is not null)
                    .Select(e => e.ClassName!).Distinct().Take(12)));
        }

        int flush = events.Count(e => e.Ring == "nmethodflushes");
        if (deadBlobs.Count > 0 && flush == 0 && redef == 0)
        {
            sb.AppendLine(L("  MISMATCH: the cache holds code of methods that no longer exist,", "  DISCREPANCIA: la caché contiene código de métodos que ya no existen,"));
            sb.AppendLine(L("  while the logs are silent about it.", "  mientras los registros callan."));
            var f = ctx.Report.Report("JVM",
                L($"{deadBlobs.Count} compiled methods in the code cache refer to unreachable Method objects, with empty redefinition and method flush logs", $"{deadBlobs.Count} métodos compilados de la caché de código apuntan a objetos Method inalcanzables, con los registros de redefinición y de descarte de métodos vacíos"),
                Severity.High,
                L("Compiled code outlives its method in two cases: the class was unloaded or the class was redefined. The virtual machine records both in its logs. There is code but no entries — so a third source (the code cache) remembers an event the other two are silent about. Such a mismatch requires manual review by itself: these nmethods show exactly which game methods had their code replaced.", "El código compilado sobrevive a su método en dos casos: la clase se descargó o la clase se redefinió. La máquina virtual registra ambos casos en sus registros. Hay código pero no entradas: por tanto, una tercera fuente (la caché de código) recuerda un evento sobre el que las otras dos callan. Una discrepancia así requiere revisión manual por sí misma: estos nmethod muestran exactamente qué métodos del juego tuvieron su código sustituido."));
            foreach (var b in deadBlobs.Take(30))
                f.Add($"nmethod 0x{b.Address:X}",
                    L($"Method 0x{b.Method:X} unreachable, state {StateName(b.State)}, blob name «{b.Name}»", $"Method 0x{b.Method:X} inalcanzable, estado {StateName(b.State)}, nombre del bloque «{b.Name}»"));
        }

        if (redef == 0 && oldMethods.Count == 0 && deadBlobs.Count == 0)
            sb.AppendLine(L("  All sources agree with each other: there are no traces of redefinition.", "  Todas las fuentes coinciden entre sí: no hay rastros de redefinición."));
        sb.AppendLine();
    }

    private static void ReportEpisodes(ScanContext ctx, List<Episode> episodes)
    {
        if (episodes.Count == 0) return;

        DateTime start = ctx.Target.StartTimeUtc;
        var f = ctx.Report.Report("JVM",
            L($"The virtual machine log has {episodes.Count} class redefinition episodes", $"El registro de la máquina virtual tiene {episodes.Count} episodios de redefinición de clases"),
            Severity.Critical,
            L("On-the-fly class redefinition (RedefineClasses / RetransformClasses) is a capability available only to a JVMTI agent. The game does not redefine its classes: it has no reason to, all its code is loaded from archives once. Each such entry was made by the virtual machine itself, contains the class name and the time, and means someone\'s agent replaced game code right in the running process. Each episode below comes with everything that happened near it in time: this context shows what exactly the VM did next — flushed compiled code, deoptimized methods, loaded new classes.", "La redefinición de clases en caliente (RedefineClasses / RetransformClasses) es una capacidad disponible solo para un agente JVMTI. El juego no redefine sus clases: no tiene motivos, todo su código se carga una vez desde los archivos. Cada entrada así la escribió la propia máquina virtual, contiene el nombre de la clase y la hora, y significa que el agente de alguien sustituyó código del juego directamente en el proceso en ejecución. Cada episodio de abajo incluye todo lo que ocurrió cerca en el tiempo: ese contexto muestra qué hizo exactamente la VM a continuación (descartar código compilado, desoptimizar métodos, cargar clases nuevas)."));
        foreach (var ep in episodes.Take(30))
        {
            string wall = start == default ? ""
                : ", " + start.AddSeconds(ep.Redefine.Ts).ToString("HH:mm:ss.fff") + " UTC";
            f.Add(L($"+{ep.Redefine.Ts:F3} s{wall}", $"+{ep.Redefine.Ts:F3} s{wall}"),
                L($"{ep.Redefine.Text} — methods with flags: {ep.OldMethods.Count}, events nearby: {ep.Nearby.Count}", $"{ep.Redefine.Text}: métodos con banderas: {ep.OldMethods.Count}, eventos cercanos: {ep.Nearby.Count}"));
        }

        var body = new StringBuilder();
        foreach (var ep in episodes.Take(12))
        {
            body.AppendLine(L($"+{ep.Redefine.Ts:F3} s  {ep.Redefine.Text}", $"+{ep.Redefine.Ts:F3} s  {ep.Redefine.Text}"));
            foreach (var e in ep.Nearby.OrderBy(x => x.Ts).Take(24))
                body.AppendLine(L($"    +{e.Ts:F3} s  [{e.Ring}]  {Cut(e.Text, 110)}", $"    +{e.Ts:F3} s  [{e.Ring}]  {Cut(e.Text, 110)}"));
            body.AppendLine();
        }
        f.Block(L("Episode context in time", "Contexto temporal de los episodios"), body.ToString().TrimEnd());
    }

    private static void ReportBands(ScanContext ctx, List<Band> bands, bool redefinitionSeen)
    {
        var big = bands.Where(b => b.Count >= 8).ToList();
        if (big.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            L($"{big.Count} contiguous bands of invalid compiled code (the largest is {big.Max(b => b.Count)} methods in a row)", $"{big.Count} bandas contiguas de código compilado no válido (la mayor tiene {big.Max(b => b.Count)} métodos seguidos)") +
            (redefinitionSeen ? "" : L(" — redefinition not confirmed by other sources", ": redefinición no confirmada por otras fuentes")),
            redefinitionSeen ? Severity.Medium : Severity.Low,
            L("The code cache allocator hands out memory sequentially, so the order of blocks by address is the order of their compilation. Ordinary deoptimization knocks out individual methods, and invalid blocks end up scattered among valid ones. A contiguous band means a large group of methods was declared invalid AT ONCE. This is exactly how class redefinition works: it throws away the compiled code of all methods of the class at once. A band is not evidence by itself — mass deoptimization on a compilation level change looks the same — but its position and width show where to look for the event that caused it.", "El asignador de la caché de código entrega la memoria de forma secuencial, así que el orden de los bloques por dirección es el orden de su compilación. Una desoptimización corriente elimina métodos aislados, y los bloques no válidos quedan dispersos entre los válidos. Una banda contigua significa que un grupo grande de métodos se declaró no válido DE UNA VEZ. Así funciona exactamente la redefinición de clases: descarta de golpe el código compilado de todos los métodos de la clase. Una banda no es una prueba por sí sola (una desoptimización masiva al cambiar de nivel de compilación se ve igual), pero su posición y anchura muestran dónde buscar el evento que la causó."));
        foreach (var b in big.OrderByDescending(x => x.Count).Take(20))
        {
            var names = b.Blobs.Select(x => x.Name).Where(x => x.Length > 0)
                               .Distinct().Take(4);
            f.Add(L($"{b.Count} in a row", $"{b.Count} seguidos"),
                L($"addresses 0x{b.Blobs[0].Lo:X}…0x{b.Blobs[^1].Hi:X}, states: {string.Join("/", b.Blobs.Select(x => StateName(x.State)).Distinct())}", $"direcciones 0x{b.Blobs[0].Lo:X}…0x{b.Blobs[^1].Hi:X}, estados: {string.Join("/", b.Blobs.Select(x => StateName(x.State)).Distinct())}") +
                (names.Any() ? L(", for example ", ", por ejemplo ") + string.Join(", ", names) : ""));
        }
    }

    private static void ReportDeoptStorm(ScanContext ctx, List<Ev> events, StringBuilder sb)
    {
        var deopt = events.Where(e => e.Ring == "deopt").OrderBy(e => e.Ts).ToList();
        if (deopt.Count < 4) return;

        var clusters = new List<List<Ev>>();
        var cur = new List<Ev> { deopt[0] };
        for (int i = 1; i < deopt.Count; i++)
        {
            if (deopt[i].Ts - deopt[i - 1].Ts <= 0.25) cur.Add(deopt[i]);
            else { clusters.Add(cur); cur = new List<Ev> { deopt[i] }; }
        }
        clusters.Add(cur);

        var storms = clusters.Where(c => c.Count >= 8).ToList();
        sb.AppendLine(L("DEOPTIMIZATION DENSITY", "DENSIDAD DE DESOPTIMIZACIONES"));
        sb.AppendLine(L($"  entries in the ring: {deopt.Count}, clusters (step ≤ 0.25 s): {clusters.Count}, dense ones (8 or more): {storms.Count}", $"  entradas en el anillo: {deopt.Count}, grupos (paso ≤ 0,25 s): {clusters.Count}, densos (8 o más): {storms.Count}"));
        foreach (var c in clusters.OrderByDescending(x => x.Count).Take(10))
            sb.AppendLine(L($"      {c.Count,4} entries in {c[^1].Ts - c[0].Ts:F3} s, starting at +{c[0].Ts:F3} s", $"      {c.Count,4} entradas en {c[^1].Ts - c[0].Ts:F3} s, desde +{c[0].Ts:F3} s"));
        sb.AppendLine();

        if (storms.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            L($"{storms.Count} dense deoptimization bursts (the largest is {storms.Max(s => s.Count)} entries in a row)", $"{storms.Count} ráfagas densas de desoptimización (la mayor tiene {storms.Max(s => s.Count)} entradas seguidas)"),
            Severity.Medium,
            L("Deoptimization by itself is normal work of the optimizing compiler: it makes assumptions about code and rolls them back when they stop holding. But during warm-up these events are SPREAD over time: methods are relearned one by one. A dense burst — dozens of entries in fractions of a second — means one event invalidated a large piece of compiled code. Class redefinition and replacement of its methods look exactly like this. Compare the burst time with the episodes above and with the class loading log.", "La desoptimización por sí sola es trabajo normal del compilador optimizador: hace suposiciones sobre el código y las revierte cuando dejan de cumplirse. Pero durante el calentamiento estos eventos están REPARTIDOS en el tiempo: los métodos se reaprenden uno a uno. Una ráfaga densa (decenas de entradas en fracciones de segundo) significa que un solo evento invalidó un trozo grande de código compilado. La redefinición de clases y la sustitución de sus métodos se ven exactamente así. Compare la hora de la ráfaga con los episodios de arriba y con el registro de carga de clases."));
        foreach (var s in storms.OrderByDescending(x => x.Count).Take(12))
            f.Add(L($"+{s[0].Ts:F3} s", $"+{s[0].Ts:F3} s"),
                L($"{s.Count} deoptimizations in {s[^1].Ts - s[0].Ts:F3} s; first: ", $"{s.Count} desoptimizaciones en {s[^1].Ts - s[0].Ts:F3} s; la primera: ") +
                Cut(s[0].Text, 110));
    }

    private static void ReportOrphanDeoptState(ScanContext ctx, List<CodeBlobInfo> invalid,
        StringBuilder sb)
    {
        if (invalid.Count == 0) return;

        var byState = invalid.GroupBy(b => b.State)
                             .ToDictionary(g => g.Key, g => g.Count());
        sb.AppendLine(L("INVALID CODE STATES", "ESTADOS DEL CÓDIGO NO VÁLIDO"));
        foreach (var kv in byState.OrderByDescending(x => x.Value))
            sb.AppendLine($"      {StateName(kv.Key),-16} {kv.Value}");
        sb.AppendLine();

        var liveMethodInvalid = invalid
            .Where(b => b.Method != 0 && ctx.LiveMethods.Contains(b.Method))
            .ToList();
        if (liveMethodInvalid.Count == 0 || ctx.LiveMethods.Count == 0) return;

        double share = (double)liveMethodInvalid.Count /
                       Math.Max(1, ctx.CodeBlobs.Count(b => b.IsNmethod));
        if (share < 0.10) return;

        ctx.Report.Report("JVM",
                L($"{liveMethodInvalid.Count} compiled methods are invalid although the methods themselves are alive and reachable ({share:P0} of the whole cache)", $"{liveMethodInvalid.Count} métodos compilados no son válidos aunque los propios métodos están vivos y son alcanzables ({share:P0} de toda la caché)"),
                Severity.Low,
                L("Invalid code with a live method is the normal course of things: the compiler rolled back an assumption and the method will be recompiled. The share matters: when a noticeable part of the whole cache turns out invalid, it is no longer individual rollbacks but mass invalidation. The line is given as a background measure to compare the invalidation bands and deoptimization bursts above against.", "El código no válido con un método vivo es lo normal: el compilador revirtió una suposición y el método se recompilará. Lo que importa es la proporción: cuando una parte notable de toda la caché resulta no válida, ya no son reversiones aisladas, sino una invalidación masiva. La línea se da como medida de fondo con la que comparar las bandas de invalidación y las ráfagas de desoptimización de arriba."))
            .Add(L("invalid with a live method", "no válidos con método vivo"), liveMethodInvalid.Count.ToString())
            .Add(L("compiled methods total", "métodos compilados en total"),
                ctx.CodeBlobs.Count(b => b.IsNmethod).ToString())
            .Add(L("cache share", "proporción de la caché"), $"{share:P1}");
    }

    private static string? ExtractClassName(string text)
    {
        const string nameEq = "name=";
        int i = text.IndexOf(nameEq, StringComparison.Ordinal);
        if (i >= 0)
        {
            int s = i + nameEq.Length;
            int e = s;
            while (e < text.Length && text[e] != ',' && text[e] != ' ') e++;
            if (e > s) return text.Substring(s, e - s);
        }

        int q = text.IndexOf('\'');
        if (q >= 0)
        {
            int e = text.IndexOf('\'', q + 1);
            if (e > q + 1) return text.Substring(q + 1, e - q - 1);
        }

        const string cls = "class ";
        i = text.IndexOf(cls, StringComparison.Ordinal);
        if (i < 0) return null;
        int st = i + cls.Length;
        int en = st;
        while (en < text.Length && text[en] != ' ' && text[en] != ',') en++;
        return en > st ? text.Substring(st, en - st) : null;
    }

    private static string StateName(sbyte s) => s switch
    {
        0 => "in_use",
        1 => "not_used",
        2 => "not_entrant",
        3 => "zombie",
        4 => "unloaded",
        -1 => "not_installed",
        _ => L($"state {s}", $"estado {s}"),
    };

    private static string Cut(string s, int n) =>
        s.Length <= n ? s : s.Substring(0, n - 1) + "…";
}
