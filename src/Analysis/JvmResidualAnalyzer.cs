using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JvmResidualAnalyzer
{
    private const uint JVMTI_MAGIC = 0x71EE;
    private const uint DISPOSED_MAGIC = 0xDEFC;
    private const uint BAD_MAGIC = 0xDEAD;

    private static readonly string[] AgentThreadMarkers =
    {
        "JVMTI", "Agent", "ByteBuddy", "Byte Buddy", "Javassist", "Instrument",
        "JDWP", "Attach",
    };

    private static readonly string[] AgentModuleNames =
    {
        "instrument.dll", "jdwp.dll", "attach.dll", "dt_socket.dll", "dt_shmem.dll",
    };

    public static void Run(ScanContext ctx, List<VmTable> tables, SweepResult sweep)
    {
        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null) return;

        var sb = new StringBuilder();
        var envs = FindJvmtiEnvironments(ctx, jvm, tables, sweep, sb);
        if (envs.Count > 0) WalkAgentList(ctx, envs, jvm, sb);
        ReportEnvironments(ctx, jvm, envs, sb);
        FindAgentHolders(ctx, envs, sb);
        CheckAgentThreads(ctx, sb);
        CheckInstrumentResiduals(ctx, sweep, sb);

        ctx.Report.Section(L("RESIDUAL JVM STATE (traces of a JVMTI agent)", "ESTADO RESIDUAL DE LA JVM (rastros de un agente JVMTI)"), sb.ToString());
    }

    private sealed class JvmtiEnv
    {
        public ulong Address;
        public ulong FunctionTable;
        public uint Magic;
        public uint Version;
        public MemRegion? Region;
        public List<(int Off, ulong Val)> ForeignPointers = new();
        public byte[]? Dump;

        public string MagicName => Magic switch
        {
            JVMTI_MAGIC => L("0x71EE JVMTI_MAGIC (environment active)", "0x71EE JVMTI_MAGIC (entorno activo)"),
            DISPOSED_MAGIC => L("0xDEFC DISPOSED_MAGIC (environment DISABLED)", "0xDEFC DISPOSED_MAGIC (entorno DESACTIVADO)"),
            BAD_MAGIC => L("0xDEAD BAD_MAGIC (environment retired)", "0xDEAD BAD_MAGIC (entorno retirado)"),
            _ => L($"0x{Magic:X} (does not match the known ones)", $"0x{Magic:X} (no coincide con los conocidos)"),
        };
    }

    private static List<JvmtiEnv> FindJvmtiEnvironments(ScanContext ctx, ImageInMemory jvm,
        List<VmTable> tables, SweepResult sweep, StringBuilder sb)
    {
        var res = new List<JvmtiEnv>();
        var jvmti = tables.FirstOrDefault(t => t.Kind.StartsWith("jvmtiInterface"));
        sb.AppendLine(jvmti is null
            ? L("The jvmtiInterface_1_ table in jvm.dll was not identified — agent environments are searched only by magic numbers.", "No se identificó la tabla jvmtiInterface_1_ en jvm.dll: los entornos de agentes solo se buscan por números mágicos.")
            : L($"jvmtiInterface_1_ table: 0x{jvmti.Address:X} ({jvmti.Slots} slots)", $"Tabla jvmtiInterface_1_: 0x{jvmti.Address:X} ({jvmti.Slots} entradas)"));

        var needles = new List<ulong>();
        if (jvmti is not null) needles.Add(jvmti.Address);

        var candidates = new List<ulong>();

        if (jvmti?.RefPattern is not null && jvmti.RefPattern.Hits.Count > 0)
        {
            foreach (var (addr, _) in jvmti.RefPattern.Hits) candidates.Add(addr);
            sb.AppendLine(L($"References to the table from the full scan: {jvmti.RefPattern.TotalHits}", $"Referencias a la tabla desde el escaneo completo: {jvmti.RefPattern.TotalHits}"));
        }
        else if (needles.Count > 0)
        {
            int found = 0;
            var needle = BitConverter.GetBytes(needles[0]);
            foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateAnyData, overlap: 8))
            {
                int pos = 0;
                while (pos < ch.Length)
                {
                    int idx = ch.Data.AsSpan(pos, ch.Length - pos).IndexOf(needle);
                    if (idx < 0) break;
                    candidates.Add(ch.Base + (ulong)(pos + idx));
                    pos += idx + 1;
                    if (++found > 4096) break;
                }
                if (found > 4096) break;
            }
            sb.AppendLine(L($"References to the table found by the own scan: {candidates.Distinct().Count()} (all private memory scanned, ", $"Referencias a la tabla encontradas con el escaneo propio: {candidates.Distinct().Count()} (revisada toda la memoria privada, ") +
                          MemoryAnalyzer.Human(MemoryScan.TotalReadable(ctx, MemoryScan.PrivateAnyData)) + ")");
        }

        foreach (var addr in candidates.Distinct().Take(8192))
        {
            var head = ctx.Target.ReadBytes(addr, 0x18);
            if (head is null) continue;
            ulong fnTable = BitConverter.ToUInt64(head, 0);
            uint magic = BitConverter.ToUInt32(head, 8);
            uint version = BitConverter.ToUInt32(head, 12);
            if (magic is not (JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC)) continue;

            var env = new JvmtiEnv
            {
                Address = addr,
                FunctionTable = fnTable,
                Magic = magic,
                Version = version,
                Region = ctx.RegionAt(addr),
            };
            env.Dump = ctx.Target.ReadBytes(addr, 0x400);
            if (env.Dump is not null)
            {
                for (int i = 0; i + 8 <= env.Dump.Length; i += 8)
                {
                    ulong v = BitConverter.ToUInt64(env.Dump, i);
                    if (v is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                    if (v >= jvm.Base && v < jvm.End) continue;
                    var reg = ctx.RegionAt(v);
                    if (reg is null || !reg.IsCommitted || !reg.IsExecutable) continue;
                    env.ForeignPointers.Add((i, v));
                }
            }
            res.Add(env);
            if (res.Count > 64) break;
        }

        if (res.Count == 0 && jvmti is null)
            sb.AppendLine(L("Magic number search without a known table was not performed: too many false matches on two bytes.", "No se hizo la búsqueda por números mágicos sin una tabla conocida: demasiadas coincidencias falsas con dos bytes."));

        sb.AppendLine(L($"jvmtiEnv objects identified: {res.Count} (active: {res.Count(x => x.Magic == JVMTI_MAGIC)}, disabled: {res.Count(x => x.Magic == DISPOSED_MAGIC)}, retired: {res.Count(x => x.Magic == BAD_MAGIC)})", $"Objetos jvmtiEnv identificados: {res.Count} (activos: {res.Count(x => x.Magic == JVMTI_MAGIC)}, desactivados: {res.Count(x => x.Magic == DISPOSED_MAGIC)}, retirados: {res.Count(x => x.Magic == BAD_MAGIC)})"));
        sb.AppendLine();
        return res;
    }

    private static void ReportEnvironments(ScanContext ctx, ImageInMemory jvm,
        List<JvmtiEnv> envs, StringBuilder sb)
    {
        foreach (var env in envs)
        {
            sb.AppendLine(L($"jvmtiEnv 0x{env.Address:X}  magic={env.MagicName}  version=0x{env.Version:X}  {env.Region?.TypeString}/{env.Region?.ProtectString}  foreign pointers: {env.ForeignPointers.Count}", $"jvmtiEnv 0x{env.Address:X}  magic={env.MagicName}  version=0x{env.Version:X}  {env.Region?.TypeString}/{env.Region?.ProtectString}  punteros ajenos: {env.ForeignPointers.Count}"));

            Severity sev = env.Magic switch
            {
                DISPOSED_MAGIC => Severity.Critical,
                JVMTI_MAGIC => Severity.Critical,
                _ => Severity.High,
            };

            string why = env.Magic == DISPOSED_MAGIC
                ? L("A JVMTI environment object marked as DISABLED was found. HotSpot sets this value in DisposeEnvironment — so an agent was attached to this JVM and then disabled itself. This is exactly what the «unhook» of a JVMTI cheat looks like: the agent library is unloaded, classes are restored, but the environment object stays in the heap with the disabled mark until this memory is reused. A clean Minecraft client has no jvmtiEnv objects at all, neither active nor disabled.", "Se encontró un objeto de entorno JVMTI marcado como DESACTIVADO. HotSpot pone este valor en DisposeEnvironment: por tanto, un agente se conectó a esta JVM y luego se desactivó a sí mismo. Así es exactamente el «unhook» de un cheat JVMTI: la biblioteca del agente se descarga, las clases se restauran, pero el objeto de entorno permanece en el heap con la marca de desactivado hasta que esa memoria se reutiliza. Un cliente de Minecraft limpio no tiene ningún objeto jvmtiEnv, ni activo ni desactivado.")
                : env.Magic == JVMTI_MAGIC
                    ? L("An ACTIVE JVMTI environment object was found. Every agent attached to the JVM receives such an object; a Minecraft client without agents has none. The agent has full access to bytecode, classes, fields and stacks — this is the mechanism of JVMTI cheats.", "Se encontró un objeto de entorno JVMTI ACTIVO. Cada agente conectado a la JVM recibe un objeto así; un cliente de Minecraft sin agentes no tiene ninguno. El agente tiene acceso total al bytecode, las clases, los campos y las pilas: es el mecanismo de los cheats JVMTI.")
                    : L("A JVMTI environment object with the corrupted mark was found. It is a trace of an agent whose environment the JVM considered invalid.", "Se encontró un objeto de entorno JVMTI con la marca de corrupto. Es el rastro de un agente cuyo entorno la JVM consideró no válido.");

            var f = ctx.Report.Report("JVM",
                L($"JVMTI environment object at 0x{env.Address:X}: {env.MagicName}", $"Objeto de entorno JVMTI en 0x{env.Address:X}: {env.MagicName}"), sev, why);
            f.Add(L("object address (jvmtiEnv*)", "dirección del objeto (jvmtiEnv*)"), env.Address);
            f.Add(L("function table", "tabla de funciones"), $"0x{env.FunctionTable:X} → {ctx.Describe(env.FunctionTable)}");
            f.Add("magic", env.MagicName);
            f.Add(L("version field", "campo version"), $"0x{env.Version:X}");
            f.Add(L("region", "región"), env.Region?.ToString() ?? "-");
            f.Add(L("pointers to code outside jvm.dll", "punteros a código fuera de jvm.dll"), env.ForeignPointers.Count.ToString());

            if (env.ForeignPointers.Count > 0)
            {
                var body = new StringBuilder();
                foreach (var (off, v) in env.ForeignPointers.Take(48))
                {
                    var im = ctx.ImageAt(v);
                    bool alien = im is null || im.Ldr is null;
                    body.AppendLine($"  {(alien ? "!!" : "  ")} +0x{off:X3}  0x{v:X}  " +
                                    ctx.Describe(v));
                }
                f.Block(L("Pointers from the object body (agent event callbacks)", "Punteros desde el cuerpo del objeto (callbacks de eventos del agente)"),
                    body.ToString().TrimEnd());

                if (env.ForeignPointers.Any(p => ctx.ImageAt(p.Val)?.Ldr is null))
                {
                    ctx.Report.Report("JVM",
                            L($"JVMTI environment 0x{env.Address:X} holds callbacks leading to memory outside loaded modules", $"El entorno JVMTI 0x{env.Address:X} guarda callbacks que apuntan a memoria fuera de los módulos cargados"),
                            Severity.Critical,
                            L("The JVMTI event callback table inside the environment object holds addresses of agent functions. If these addresses point where there is no loaded module any more, the agent library has already been unloaded while its addresses remained — direct proof that the agent was running and was removed.", "La tabla de callbacks de eventos JVMTI dentro del objeto de entorno guarda las direcciones de las funciones del agente. Si estas direcciones apuntan donde ya no hay ningún módulo cargado, la biblioteca del agente ya se descargó mientras sus direcciones permanecieron: una prueba directa de que el agente se ejecutó y fue retirado."))
                        .Add(L("environment object", "objeto de entorno"), env.Address)
                        .Add(L("callbacks outside modules", "callbacks fuera de módulos"),
                            env.ForeignPointers.Count(p => ctx.ImageAt(p.Val)?.Ldr is null).ToString());
                }
            }

            DecodeEventCallbacks(ctx, env, jvm, f);

            if (env.Dump is not null)
                f.Block(L("Environment object (0x400 bytes; jvmtiCapabilities and the event callback table also lie here)", "Objeto de entorno (0x400 bytes; aquí también están jvmtiCapabilities y la tabla de callbacks de eventos)"), HexDump.Format(env.Dump, env.Address));

            if (ctx.Dumper is not null)
            {
                ulong from = env.Address > 0x1000 ? env.Address - 0x1000 : env.Address;
                string? p = ctx.Dumper.DumpRange(from, 0x4000, "jvmtienv",
                    L($"JVMTI environment object ({env.MagicName}) and its neighbourhood in the heap", $"objeto de entorno JVMTI ({env.MagicName}) y su entorno en el heap"),
                    L($"the object itself at 0x{env.Address:X}, file offset 0x{env.Address - from:X}", $"el propio objeto en 0x{env.Address:X}, desplazamiento en el archivo 0x{env.Address - from:X}"));
                if (p is not null) f.Add(L("neighbourhood dump", "volcado del entorno"), p);
            }
        }
        if (envs.Count > 0) sb.AppendLine();
    }

    private static void WalkAgentList(ScanContext ctx, List<JvmtiEnv> envs, ImageInMemory jvm,
        StringBuilder sb)
    {
        const int NextOffset = 0x10;
        var known = envs.Select(e => e.Address).ToHashSet();
        var added = new List<JvmtiEnv>();

        foreach (var start in envs.ToList())
        {
            ulong p = ctx.Target.ReadU64(start.Address + NextOffset);
            int guard = 0;
            while (p is >= 0x10000 and <= 0x7FFFFFFFFFFF && guard++ < 64)
            {
                if (!known.Add(p)) break;

                var head = ctx.Target.ReadBytes(p, 0x18);
                if (head is null) break;
                ulong fnTable = BitConverter.ToUInt64(head, 0);
                uint magic = BitConverter.ToUInt32(head, 8);
                bool looksLikeEnv = magic is JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC ||
                                    (fnTable >= jvm.Base && fnTable < jvm.End);
                if (!looksLikeEnv) break;

                var env = new JvmtiEnv
                {
                    Address = p,
                    FunctionTable = fnTable,
                    Magic = magic,
                    Version = BitConverter.ToUInt32(head, 12),
                    Region = ctx.RegionAt(p),
                    Dump = ctx.Target.ReadBytes(p, 0x400),
                };
                added.Add(env);
                p = BitConverter.ToUInt64(head, NextOffset);
            }
        }

        if (added.Count > 0)
        {
            sb.AppendLine(L($"Walking the environment list via the _next field added {added.Count} environments not found by scanning:", $"Recorrer la lista de entornos por el campo _next añadió {added.Count} entornos no encontrados en el escaneo:"));
            foreach (var e in added)
                sb.AppendLine($"  0x{e.Address:X}  {e.MagicName}");
            sb.AppendLine();

            ctx.Report.Report("JVM",
                    L($"The JVMTI environment list contains {added.Count} environments that are not found by scanning memory", $"La lista de entornos JVMTI contiene {added.Count} entornos que no se encuentran escaneando la memoria"),
                    Severity.Critical,
                    L("The virtual machine links all agent environments in a singly linked list. Walking it from a found environment produced additional ones — the search by references to the function table did not find them, so this field is already wiped or changed on them. This is what an attempt to hide the fact of agent attachment looks like: the object itself was not removed from the list, but its identifying feature was stripped.", "La máquina virtual enlaza todos los entornos de agentes en una lista simplemente enlazada. Al recorrerla desde un entorno encontrado aparecieron otros: la búsqueda por referencias a la tabla de funciones no los encontró, así que en ellos ese campo ya está borrado o modificado. Así se ve un intento de ocultar la conexión de un agente: el objeto no se sacó de la lista, pero se le quitó el rasgo que lo identifica."))
                .Add(L("found by walking the list", "encontrados al recorrer la lista"), added.Count.ToString())
                .Block(L("Environments", "Entornos"), string.Join("\n", added.Select(e =>
                    L($"  0x{e.Address:X}  magic={e.MagicName}  table={ctx.Describe(e.FunctionTable)}", $"  0x{e.Address:X}  magic={e.MagicName}  tabla={ctx.Describe(e.FunctionTable)}"))));

            envs.AddRange(added);
        }
        else sb.AppendLine(L("Walking the environment list gave no new objects.", "Recorrer la lista de entornos no dio objetos nuevos."));
        sb.AppendLine();
    }

    private static void DecodeEventCallbacks(ScanContext ctx, JvmtiEnv env, ImageInMemory jvm,
        Finding f)
    {
        if (env.Dump is null) return;

        var layout = JvmtiEnvLayout.Probe(ctx, env.Dump);
        if (layout is null)
        {
            f.Add(L("event callback table", "tabla de callbacks de eventos"),
                L("NOT IDENTIFIED — none of the checked offsets passed verification (callbacks must be zeros or executable memory addresses). No conclusions about subscriptions are drawn for this object.", "NO IDENTIFICADA: ninguno de los desplazamientos comprobados pasó la verificación (los callbacks deben ser ceros o direcciones de memoria ejecutable). No se sacan conclusiones sobre suscripciones para este objeto."));
            return;
        }

        f.Add(L("event callback table", "tabla de callbacks de eventos"), L($"offset +0x{layout.Callbacks:X} in the object", $"desplazamiento +0x{layout.Callbacks:X} en el objeto"));
        f.Add(L("event enable masks", "máscaras de activación de eventos"),
            layout.AnyEventEnabled
                ? $"user=0x{layout.Masks[0]:X16} callback=0x{layout.Masks[1]:X16} " +
                  $"enabled=0x{layout.Masks[2]:X16}"
                : L("all three are zero — no event is enabled at the time of the check", "las tres son cero: ningún evento está activado en el momento de la comprobación"));

        var callbacks = JvmtiEnvLayout.Callbacks(env.Dump, layout);
        if (callbacks.Count == 0)
        {
            f.Add(L("event subscriptions", "suscripciones a eventos"),
                L("the callback table was identified and is EMPTY — handlers were removed or never set", "la tabla de callbacks se identificó y está VACÍA: los manejadores se quitaron o nunca se pusieron"));
            return;
        }

        var subscribed = callbacks
            .Select(x => $"{x.Event} → {ctx.Describe(x.Target)}")
            .ToList();
        f.Block(L("JVMTI event subscriptions (pointer position = event)", "Suscripciones a eventos JVMTI (posición del puntero = evento)"),
            string.Join("\n", subscribed.Select(x => "  " + x)));

        var cflh = callbacks.FirstOrDefault(x => x.Event == "ClassFileLoadHook");
        if (cflh.Target == 0) return;

        bool outsideModules = ctx.ImageAt(cflh.Target) is null;
        ctx.Report.Report("JVM",
                L($"JVMTI environment 0x{env.Address:X} holds a ClassFileLoadHook handler", $"El entorno JVMTI 0x{env.Address:X} tiene un manejador de ClassFileLoadHook"),
                Severity.Critical,
                L("ClassFileLoadHook is the event through which an agent receives the bytecode of EVERY loaded class and returns a modified one. It is the main mechanism of a Java cheat: replacing game code on the fly. The handler address is recorded in the callback table of the environment itself and stays there after the agent has finished: SetEventNotificationMode disables the event but does not clear the callback table. The table offset here is not guessed but verified: all its slots are either zero or lead to committed executable memory, and the object tail matches the JvmtiEnvBase layout.", "ClassFileLoadHook es el evento mediante el cual un agente recibe el bytecode de CADA clase que se carga y devuelve uno modificado. Es el mecanismo principal de un cheat de Java: sustituir el código del juego en caliente. La dirección del manejador queda registrada en la tabla de callbacks del propio entorno y permanece ahí después de que el agente termine: SetEventNotificationMode desactiva el evento, pero no limpia la tabla de callbacks. Aquí el desplazamiento de la tabla no se adivina, se verifica: todas sus entradas son cero o apuntan a memoria ejecutable comprometida, y la cola del objeto coincide con la disposición de JvmtiEnvBase."))
            .Add(L("environment object", "objeto de entorno"), env.Address)
            .Add(L("environment state", "estado del entorno"), env.MagicName)
            .Add(L("handler address", "dirección del manejador"), $"0x{cflh.Target:X} — {ctx.Describe(cflh.Target)}")
            .Add(L("handler outside loaded modules", "manejador fuera de los módulos cargados"), outsideModules ? L("YES", "SÍ") : L("no", "no"))
            .Add(L("event enabled now", "evento activado ahora"),
                layout.AnyEventEnabled ? L("masks non-zero", "máscaras distintas de cero") : L("no, masks are zeroed", "no, las máscaras están a cero"))
            .Block(L("Subscriptions", "Suscripciones"), string.Join("\n", subscribed.Select(x => "  " + x)));
    }

    private static void FindAgentHolders(ScanContext ctx, List<JvmtiEnv> envs, StringBuilder sb)
    {
        if (envs.Count == 0) return;

        var needles = envs.Select(e => BitConverter.GetBytes(e.Address)).ToList();
        var holders = new List<(ulong Addr, ulong Env, MemRegion Region)>();
        var seenHolders = new HashSet<ulong>();

        foreach (var ch in MemoryScan.Chunks(ctx,
                     r => MemoryScan.Readable(r) &&
                          !(r.IsImage && r.MappedFile is not null && !r.IsWritable)))
        {
            if (holders.Count > 256) break;
            for (int k = 0; k < needles.Count; k++)
            {
                int pos = 0;
                while (pos < ch.Length)
                {
                    int idx = ch.Data.AsSpan(pos, ch.Length - pos).IndexOf(needles[k]);
                    if (idx < 0) break;
                    ulong at = ch.Base + (ulong)(pos + idx);
                    pos += idx + 1;
                    if (at == envs[k].Address) continue;
                    if (!seenHolders.Add(at)) continue;
                    holders.Add((at, envs[k].Address, ch.Region));
                    if (holders.Count > 256) break;
                }
            }
        }

        sb.AppendLine(L($"Structures holding a pointer to a JVMTI environment: {holders.Count}", $"Estructuras que guardan un puntero a un entorno JVMTI: {holders.Count}"));
        foreach (var h in holders.Take(64))
            sb.AppendLine($"  0x{h.Addr:X}  → jvmtiEnv 0x{h.Env:X}  " +
                          $"({h.Region.TypeString}/{h.Region.ProtectString}) " +
                          (ctx.ImageAt(h.Addr)?.Name is { } n ? L($"in module {n}", $"en el módulo {n}") : ""));

        foreach (var h in holders)
        {
            var win = ctx.Target.ReadBytes(h.Addr > 0x40 ? h.Addr - 0x40 : h.Addr, 0x100);
            if (win is null) continue;
            int envPtrs = 0;
            bool javaVm = false;
            for (int i = 0; i + 8 <= win.Length; i += 8)
            {
                ulong v = BitConverter.ToUInt64(win, i);
                if (envs.Any(e => e.Address == v)) envPtrs++;
                else if (v is >= 0x10000 and <= 0x7FFFFFFFFFFF)
                {
                    ulong t = ctx.Target.ReadU64(v);
                    var im = ctx.ImageAt(t);
                    if (im is not null &&
                        im.Name.Equals("jvm.dll", StringComparison.OrdinalIgnoreCase)) javaVm = true;
                }
            }
            if (envPtrs < 2 || !javaVm) continue;

            ctx.Report.Report("JVM",
                    L($"A structure laid out like JPLISAgent (the native part of java.lang.instrument) was found at 0x{h.Addr:X}", $"En 0x{h.Addr:X} se encontró una estructura con la disposición de JPLISAgent (la parte nativa de java.lang.instrument)"),
                    Severity.Critical,
                    L("JPLISAgent is the structure that instrument.dll creates when a Java agent is attached. It is identified by its characteristic composition: a pointer to JavaVM and TWO JVMTI environments at once — the regular one and a separate one for retransform, which instrument.dll creates specifically for retransforming already loaded classes. No normal Minecraft component creates such a structure: it appears only together with -javaagent or dynamic agent attachment through the Attach API.", "JPLISAgent es la estructura que crea instrument.dll al conectar un agente Java. Se identifica por su composición característica: un puntero a JavaVM y DOS entornos JVMTI a la vez, el normal y otro aparte para retransform, que instrument.dll crea específicamente para retransformar clases ya cargadas. Ningún componente normal de Minecraft crea una estructura así: solo aparece junto con -javaagent o con la conexión dinámica de un agente mediante la Attach API."))
                .Add(L("structure address", "dirección de la estructura"), h.Addr)
                .Add(L("JVMTI environments inside", "entornos JVMTI dentro"), envPtrs.ToString())
                .Add(L("pointer to JavaVM", "puntero a JavaVM"), L("found", "encontrado"))
                .Add(L("region", "región"), h.Region.ToString())
                .Block(L("Structure", "Estructura"), HexDump.Format(win, h.Addr > 0x40 ? h.Addr - 0x40 : h.Addr));
        }

        foreach (var g in holders.GroupBy(h => h.Env))
        {
            var f = ctx.Report.Report("JVM",
                L($"JVMTI environment 0x{g.Key:X} is referenced by {g.Count()} structures in memory", $"El entorno JVMTI 0x{g.Key:X} está referenciado por {g.Count()} estructuras en memoria"),
                Severity.High,
                L("A pointer to jvmtiEnv is held by whoever uses this environment: the native part of java.lang.instrument (the JPLISAgent structure) or a custom agent. The location of these structures shows who owned the agent: an address inside instrument.dll means a normal -javaagent, an address in private memory or in a foreign module means a custom native agent.", "Un puntero a jvmtiEnv lo guarda quien usa ese entorno: la parte nativa de java.lang.instrument (la estructura JPLISAgent) o un agente propio. La ubicación de estas estructuras muestra a quién pertenecía el agente: una dirección dentro de instrument.dll significa un -javaagent normal; una dirección en memoria privada o en un módulo ajeno, un agente nativo propio."));
            foreach (var h in g.Take(32))
            {
                var im = ctx.ImageAt(h.Addr);
                f.Add(L($"holder 0x{h.Addr:X}", $"titular 0x{h.Addr:X}"),
                    (im is not null ? $"{im.Name}+0x{h.Addr - im.Base:X}" : L("private memory", "memoria privada")) +
                    $" ({h.Region.TypeString}/{h.Region.ProtectString})");
            }
            var first = g.First();
            var dump = ctx.Target.ReadBytes(
                first.Addr > 0x40 ? first.Addr - 0x40 : first.Addr, 0x100);
            if (dump is not null)
                f.Block(L("Memory around the holder", "Memoria alrededor del titular"),
                    HexDump.Format(dump, first.Addr > 0x40 ? first.Addr - 0x40 : first.Addr));
        }
        sb.AppendLine();
    }

    private static void CheckAgentThreads(ScanContext ctx, StringBuilder sb)
    {
        sb.AppendLine(L("Threads with names typical of agents and instrumentation libraries:", "Hilos con nombres típicos de agentes y bibliotecas de instrumentación:"));
        int n = 0;
        foreach (var th in ctx.Threads)
        {
            if (th.Description is null) continue;
            var hit = AgentThreadMarkers.FirstOrDefault(
                m => th.Description.Contains(m, StringComparison.OrdinalIgnoreCase));
            if (hit is null) continue;
            n++;
            double sec = ctx.Target.StartTimeUtc != default && th.CreateTimeUtc != default
                ? (th.CreateTimeUtc - ctx.Target.StartTimeUtc).TotalSeconds : -1;
            sb.AppendLine(L($"  {th.Tid,-8} +{sec,8:F1}s  «{th.Description}»  start: {ctx.Describe(th.Win32StartAddress != 0 ? th.Win32StartAddress : th.KernelStartAddress)}", $"  {th.Tid,-8} +{sec,8:F1}s  «{th.Description}»  inicio: {ctx.Describe(th.Win32StartAddress != 0 ? th.Win32StartAddress : th.KernelStartAddress)}"));

            if (th.Description.Contains("Attach Listener", StringComparison.OrdinalIgnoreCase))
                continue;
            if (hit is "Agent" or "Attach" &&
                !th.Description.Contains("JVMTI", StringComparison.OrdinalIgnoreCase) &&
                !th.Description.Contains("Agent Thread", StringComparison.OrdinalIgnoreCase))
                continue;

            ctx.Report.Report("JVM",
                    L($"Thread «{th.Description}» (TID {th.Tid}) — JVM agent infrastructure", $"Hilo «{th.Description}» (TID {th.Tid}): infraestructura de agente de la JVM"),
                    Severity.Critical,
                    L("Threads with such names are created only by agent code: JVMTI RunAgentThread, Byte Buddy, Javassist. A normal Minecraft client does not create them.", "Los hilos con estos nombres solo los crea el código de un agente: JVMTI RunAgentThread, Byte Buddy, Javassist. Un cliente de Minecraft normal no los crea."))
                .Add("TID", th.Tid.ToString())
                .Add(L("name", "nombre"), th.Description)
                .Add(L("created after", "creado tras"), sec >= 0 ? L($"{sec:F2} s after start", $"{sec:F2} s desde el inicio") : "-")
                .Add(L("start address", "dirección de inicio"), ctx.Describe(
                    th.Win32StartAddress != 0 ? th.Win32StartAddress : th.KernelStartAddress));
        }
        if (n == 0) sb.AppendLine(L("  not found", "  no encontrado"));
        sb.AppendLine();
    }

    private static readonly (string Needle, Severity Sev, string Why)[] InstrumentClasses =
    {
        ("sun/instrument/InstrumentationImpl", Severity.Critical,
            L("Implementation of java.lang.instrument.Instrumentation. Created exactly once — when a Java agent is attached. Its presence in memory means an agent attached to this JVM, even if it has already finished.", "Implementación de java.lang.instrument.Instrumentation. Se crea exactamente una vez: al conectar un agente Java. Su presencia en memoria significa que un agente se conectó a esta JVM, aunque ya haya terminado.")),
        ("sun/instrument/TransformerManager", Severity.Critical,
            L("TransformerManager holds an ARRAY of registered ClassFileTransformers. It stays in the heap after the agent has finished: removing a transformer only takes it out of the array, while the manager object itself and its traces remain.", "TransformerManager guarda un ARRAY de ClassFileTransformer registrados. Permanece en el heap después de que el agente termine: quitar un transformador solo lo saca del array, mientras el propio objeto gestor y sus rastros siguen ahí.")),
        ("java/lang/instrument/ClassFileTransformer", Severity.Critical,
            L("The interface for replacing the bytecode of loaded classes — the main tool of a Java cheat working as an agent.", "La interfaz para sustituir el bytecode de las clases cargadas: la herramienta principal de un cheat de Java que funciona como agente.")),
        ("java/lang/instrument/Instrumentation", Severity.Critical,
            L("JVM instrumentation API.", "API de instrumentación de la JVM.")),
        ("java/lang/instrument/UnmodifiableClassException", Severity.High,
            L("An exception class from java.lang.instrument: loaded together with the rest of the instrumentation API.", "Una clase de excepción de java.lang.instrument: se carga junto con el resto de la API de instrumentación.")),
        ("net/bytebuddy/agent/ByteBuddyAgent", Severity.Critical,
            L("Byte Buddy Agent — a library for attaching an agent to its own JVM (self-attach). Minecraft and Fabric do not contain it.", "Byte Buddy Agent: biblioteca para conectar un agente a su propia JVM (self-attach). Minecraft y Fabric no la contienen.")),
        ("javassist/", Severity.Medium,
            L("Javassist — a library for generating and editing bytecode at runtime.", "Javassist: biblioteca para generar y editar bytecode en tiempo de ejecución.")),
    };

    private static void CheckInstrumentResiduals(ScanContext ctx, SweepResult sweep, StringBuilder sb)
    {
        sb.AppendLine(L("Traces of java.lang.instrument in loaded classes:", "Rastros de java.lang.instrument en las clases cargadas:"));
        if (sweep.Classes.Count == 0)
        {
            sb.AppendLine(L("  full memory scan disabled — the class check was not performed", "  escaneo completo de memoria desactivado: no se hizo la comprobación de clases"));
        }
        else
        {
            foreach (var (needle, sev, why) in InstrumentClasses)
            {
                var hits = sweep.Classes.Values
                    .Where(c => c.Name.StartsWith(needle, StringComparison.Ordinal))
                    .ToList();
                sb.AppendLine(L($"  {needle,-52} {(hits.Count == 0 ? "no" : $"FOUND ×{hits.Count}")}", $"  {needle,-52} {(hits.Count == 0 ? "no" : $"ENCONTRADO ×{hits.Count}")}"));
                if (hits.Count == 0) continue;

                var f = ctx.Report.Report("JVM",
                    L($"Bytecode of «{needle}*» found in JVM memory ({hits.Count})", $"Se encontró en la memoria de la JVM bytecode de «{needle}*» ({hits.Count})"), sev, why);
                foreach (var c in hits.Take(24))
                    f.Add(c.Name, L($"0x{c.Address:X}, class version {c.MajorVersion}", $"0x{c.Address:X}, versión de clase {c.MajorVersion}") +
                                  (c.Occurrences > 1 ? L($", copies in memory: {c.Occurrences}", $", copias en memoria: {c.Occurrences}") : ""));
            }
        }
        sb.AppendLine();

        sb.AppendLine(L("Agent infrastructure modules among the loaded ones:", "Módulos de infraestructura de agentes entre los cargados:"));
        foreach (var name in AgentModuleNames)
        {
            var im = ctx.Images.FirstOrDefault(
                x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            sb.AppendLine(L($"  {name,-20} {(im is null ? "not loaded" : $"loaded, base 0x{im.Base:X}")}", $"  {name,-20} {(im is null ? "no cargado" : $"cargado, base 0x{im.Base:X}")}"));
        }
        sb.AppendLine();
        sb.AppendLine(L("Note: Agent_OnUnload is called on a native agent when its library is unloaded; traces of the agent\'s work are in the environment objects above.", "Nota: Agent_OnUnload se llama en un agente nativo cuando se descarga su biblioteca; los rastros del trabajo del agente están en los objetos de entorno de arriba."));
    }
}
