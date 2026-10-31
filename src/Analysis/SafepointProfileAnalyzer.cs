using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class SafepointProfileAnalyzer
{
    private const string Cat = "JVM";

    private static readonly (string Name, string Means)[] AgentOnly =
    {
        ("RedefineClasses", L("replacing the bytecode of an already loaded class", "sustitución del bytecode de una clase ya cargada")),
        ("ChangeBreakpoints", L("setting or clearing a breakpoint", "establecer o quitar un punto de interrupción")),
        ("ChangeSingleStep", L("single-step execution", "ejecución paso a paso")),
        ("SetFramePop", L("intercepting a return from a stack frame", "interceptar el retorno de un marco de pila")),
        ("PopFrame", L("forced exit from a stack frame", "salida forzada de un marco de pila")),
        ("ForceEarlyReturn", L("forced return from a method", "retorno forzado de un método")),
        ("GetOrSetLocal", L("reading or WRITING a local variable of another frame", "lectura o ESCRITURA de una variable local de otro marco")),
        ("GetCurrentLocation", L("querying the current execution point of a thread", "consulta del punto de ejecución actual de un hilo")),
        ("EnterInterpOnlyMode", L("switching a thread to interpreter-only mode", "cambio de un hilo al modo solo intérprete")),
        ("GetAllStackTraces", L("capturing stacks of all threads", "captura de las pilas de todos los hilos")),
        ("GetThreadListStackTraces", L("capturing stacks of selected threads", "captura de las pilas de hilos seleccionados")),
        ("GetMultipleStackTraces", L("capturing stacks of several threads", "captura de las pilas de varios hilos")),
        ("GetStackTrace", L("capturing a thread stack", "captura de la pila de un hilo")),
        ("GetObjectMonitorUsage", L("querying owners of an object lock", "consulta de los propietarios del bloqueo de un objeto")),
        ("GetOwnedMonitorInfo", L("querying locks owned by a thread", "consulta de los bloqueos que posee un hilo")),
        ("GetCurrentContendedMonitor", L("querying the lock a thread is waiting for", "consulta del bloqueo que espera un hilo")),
        ("HeapWalkOperation", L("heap walk by the VM", "recorrido del heap por la VM")),
        ("HeapIterateOperation", L("heap walk by the VM", "recorrido del heap por la VM")),
        ("ClassLoaderStats", L("collecting loader statistics", "recopilación de estadísticas de cargadores")),
        ("ClassLoaderHierarchy", L("walking the loader hierarchy", "recorrido de la jerarquía de cargadores")),
        ("ThreadDump", L("taking a full thread dump", "volcado completo de hilos")),
        ("FindDeadlocks", L("deadlock search", "búsqueda de interbloqueos")),
        ("PrintThreads", L("printing thread state", "impresión del estado de los hilos")),
        ("GetObjectSize", L("querying object size by the VM", "consulta del tamaño de un objeto por la VM")),
    };

    private static readonly string[] Ordinary =
    {
        "G1Collect", "G1Pause", "CGC_Operation", "CMS", "ParallelGCFailedAllocation",
        "GenCollect", "Cleanup", "RendezvousGCThreads", "HandshakeAllThreads",
        "ICBufferFull", "Deoptimize", "ZOperation", "ShenandoahOperation",
        "JFRCheckpoint", "JFROldObject", "Exit", "PrintCompileQueue",
        "BulkRevokeBias", "HandshakeOneThread", "G1TryInitiateConcMark",
    };

    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        sb.AppendLine(L("SAFEPOINT OPERATIONS", "OPERACIONES EN SAFEPOINTS"));
        sb.AppendLine();

        var ops = ctx.VmEvents
            .Where(e => e.Ring.Contains("VM Operation", StringComparison.OrdinalIgnoreCase) ||
                        e.Text.Contains("Executing VM operation", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (ops.Count == 0)
        {
            sb.AppendLine(L("  The VM operations ring is empty or not found. If it is not found —", "  El anillo de operaciones de la VM está vacío o no se encontró. Si no se encontró,"));
            sb.AppendLine(L("  see the black box section: it says whether the logs were disabled", "  vea la sección de la caja negra: allí se indica si los registros se desactivaron"));
            sb.AppendLine(L("  with a startup flag. The absence of entries is not evidence by itself: the ring", "  con una opción de arranque. La ausencia de entradas no es una prueba por sí sola: el anillo"));
            sb.AppendLine(L("  is small, and in a quiet game it holds only collector operations.", "  es pequeño y, en una partida tranquila, solo contiene operaciones del recolector."));
            ctx.Report.Section(L("SAFEPOINTS: OPERATION PROFILE", "SAFEPOINTS: PERFIL DE OPERACIONES"), sb.ToString());
            return;
        }

        var byName = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var e in ops)
        {
            string name = OperationName(e.Text);
            if (name.Length == 0) continue;
            byName[name] = byName.TryGetValue(name, out int c) ? c + 1 : 1;
        }

        int ordinary = 0, unknown = 0;
        var agentHits = new List<(string Name, int Count, string Means)>();
        var unknownNames = new List<string>();

        foreach (var (name, count) in byName.OrderByDescending(kv => kv.Value))
        {
            var agent = AgentOnly.FirstOrDefault(a =>
                name.Contains(a.Name, StringComparison.OrdinalIgnoreCase));
            if (agent.Name is not null)
            {
                agentHits.Add((name, count, agent.Means));
                continue;
            }
            if (Ordinary.Any(x => name.Contains(x, StringComparison.OrdinalIgnoreCase)))
            { ordinary += count; continue; }
            unknown += count;
            if (unknownNames.Count < 16) unknownNames.Add($"{name} ×{count}");
        }

        sb.AppendLine(L($"  operation entries in the ring : {ops.Count}", $"  entradas de operaciones en el anillo : {ops.Count}"));
        sb.AppendLine(L($"  distinct operation names     : {byName.Count}", $"  nombres de operación distintos       : {byName.Count}"));
        sb.AppendLine(L($"  garbage collector and upkeep : {ordinary}", $"  recolector de basura y mantenimiento : {ordinary}"));
        sb.AppendLine(L($"  ONLY FROM AN AGENT OR DEBUGGER: {agentHits.Sum(a => a.Count)} ({agentHits.Count} distinct)", $"  SOLO DE UN AGENTE O DEPURADOR       : {agentHits.Sum(a => a.Count)} ({agentHits.Count} distintas)"));
        sb.AppendLine(L($"  name not recognized          : {unknown}", $"  nombre no reconocido                : {unknown}"));
        sb.AppendLine();

        sb.AppendLine(L($"  {"OPERATION",-44} {"TIMES",-6} KIND", $"  {"OPERACIÓN",-44} {"VECES",-6} TIPO"));
        foreach (var (name, count) in byName.OrderByDescending(kv => kv.Value).Take(40))
        {
            string kind = agentHits.Any(a => a.Name == name) ? L("AGENT/DEBUGGER", "AGENTE/DEPURADOR")
                        : Ordinary.Any(x => name.Contains(x, StringComparison.OrdinalIgnoreCase))
                            ? L("collector/upkeep", "recolector/mantenimiento") : L("not recognized", "no reconocida");
            sb.AppendLine($"  {Trim(name, 43),-44} {count,-6} {kind}");
        }
        if (byName.Count > 40) sb.AppendLine(L($"  … and {byName.Count - 40} more names", $"  … y {byName.Count - 40} nombres más"));
        sb.AppendLine();

        if (agentHits.Count > 0)
        {
            sb.AppendLine(L("  OPERATIONS THE GAME ITSELF NEVER CALLS:", "  OPERACIONES QUE EL PROPIO JUEGO NUNCA LLAMA:"));
            foreach (var (name, count, means) in agentHits)
                sb.AppendLine($"    {name} ×{count} — {means}");
            sb.AppendLine();
        }

        sb.AppendLine(L("  How to read. A JVMTI agent stops the world in the normal way, and every stop", "  Cómo leerlo. Un agente JVMTI detiene el mundo de la forma normal, y cada parada"));
        sb.AppendLine(L("  lands in this ring under its own name.", "  queda en este anillo con su propio nombre."));

        if (agentHits.Count > 0)
        {
            var f = ctx.Report.Report(Cat,
                L($"The VM operations ring has {agentHits.Sum(a => a.Count)} entries of operations that come only from an agent or a debugger ({agentHits.Count} distinct)", $"El anillo de operaciones de la VM tiene {agentHits.Sum(a => a.Count)} entradas de operaciones que solo proceden de un agente o un depurador ({agentHits.Count} distintas)"),
                Severity.High,
                L("A safepoint operation is a stop of all Java threads that the VM itself performs at someone\'s request. It records each one in the «VM Operations» ring under its own name.\n\nThe game never calls the names listed below: bytecode replacement, breakpoints, single stepping, reading and writing local variables of another frame, capturing stacks of all threads, heap walks by the VM. They are called by a JVMTI agent, a debugger or a monitoring tool attached to the VM.\n\nAn entry cannot be removed from the ring: the mechanism exists for the crash report and writes unconditionally, and the ring survives both detaching the agent and unloading it. An entry can only be pushed out by noise — and then it is visible that the ring is completely full.", "Una operación en safepoint es una parada de todos los hilos Java que realiza la propia VM a petición de alguien. Cada una se registra en el anillo «VM Operations» con su propio nombre.\n\nEl juego nunca llama a los nombres que se enumeran abajo: sustitución de bytecode, puntos de interrupción, ejecución paso a paso, lectura y escritura de variables locales de otro marco, captura de las pilas de todos los hilos, recorridos del heap por la VM. Los llama un agente JVMTI, un depurador o una herramienta de monitorización conectada a la VM.\n\nUna entrada no se puede eliminar del anillo: el mecanismo existe para el informe de fallos y escribe incondicionalmente, y el anillo sobrevive tanto a la desconexión del agente como a su descarga. Una entrada solo puede desplazarse con ruido, y entonces se ve que el anillo está completamente lleno."))
                .Add(L("operation entries total", "entradas de operaciones en total"), ops.Count.ToString())
                .Add(L("collector and upkeep", "recolector y mantenimiento"), ordinary.ToString());
            foreach (var (name, count, means) in agentHits.Take(20))
                f.Add(name, $"×{count} — {means}");
        }
        else
        {
            ctx.Report.Report(Cat,
                L($"No agent or debugger operations in the VM ring: all {ops.Count} entries are the garbage collector and upkeep", $"No hay operaciones de agente o depurador en el anillo de la VM: las {ops.Count} entradas son del recolector de basura y mantenimiento"),
                Severity.Info,
                L("The safepoint operations ring was parsed by name. It contains no operation that only a JVMTI agent or a debugger calls.", "El anillo de operaciones en safepoints se analizó por nombre. No contiene ninguna operación que solo llame un agente JVMTI o un depurador."))
                .Add(L("operation entries", "entradas de operaciones"), ops.Count.ToString())
                .Add(L("distinct names", "nombres distintos"), byName.Count.ToString())
                .Add(L("unrecognized names", "nombres no reconocidos"), unknown.ToString());
        }

        if (unknownNames.Count > 0)
            sb.AppendLine(L($"  unrecognized names: {string.Join(", ", unknownNames)}", $"  nombres no reconocidos: {string.Join(", ", unknownNames)}"));

        ctx.Report.Section(L("SAFEPOINTS: OPERATION PROFILE", "SAFEPOINTS: PERFIL DE OPERACIONES"), sb.ToString());
    }

    private static string OperationName(string text)
    {
        const string marker = "VM operation:";
        int i = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        string s = i >= 0 ? text[(i + marker.Length)..] : text;
        s = s.Trim();
        if (s.EndsWith(" done", StringComparison.OrdinalIgnoreCase)) s = s[..^5].TrimEnd();
        return s.Length > 120 ? s[..120] : s;
    }

    private static string Trim(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";
}
