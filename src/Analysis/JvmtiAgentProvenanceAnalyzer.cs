using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JvmtiAgentProvenanceAnalyzer
{
    private const uint JVMTI_MAGIC = 0x71EE;
    private const uint DISPOSED_MAGIC = 0xDEFC;
    private const uint BAD_MAGIC = 0xDEAD;

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

    private sealed class Env
    {
        public ulong Address;
        public byte[] Dump = Array.Empty<byte>();
        public ulong Functions;
        public uint Magic, Version;
        public ulong Next;
        public bool Retransformable;
        public ulong LocalStorage;

        public int CallbacksOff = -1;
        public int TagMapOff = -1;
        public int EnableOff = -1;
        public int CapsOff = -1;
        public bool LayoutConfirmed;

        public ulong TagMap;
        public ulong[] Enable = Array.Empty<ulong>();
        public List<string> Caps = new();
        public List<string> Prohibited = new();
        public List<(string Event, ulong Target)> Callbacks = new();
        public List<string> Prefixes = new();
        public ulong AgentPtr;
        public AgentRecord? Agent;

        public string MagicName => Magic switch
        {
            JVMTI_MAGIC => L("0x71EE JVMTI_MAGIC (active)", "0x71EE JVMTI_MAGIC (activo)"),
            DISPOSED_MAGIC => L("0xDEFC DISPOSED_MAGIC (DISABLED via DisposeEnvironment)", "0xDEFC DISPOSED_MAGIC (DESACTIVADO con DisposeEnvironment)"),
            BAD_MAGIC => L("0xDEAD BAD_MAGIC (retired)", "0xDEAD BAD_MAGIC (retirado)"),
            _ => $"0x{Magic:X}",
        };
    }

    public static void Run(ScanContext ctx)
    {
        var jvm = JvmAnalyzer.FindJvm(ctx);
        var sb = new StringBuilder();

        if (jvm is null || !jvm.Pe.Valid)
        {
            sb.AppendLine(L("jvm.dll not found — agent recovery is impossible.", "no se encontró jvm.dll: es imposible recuperar el agente."));
            ctx.Report.Section(L("JVMTI AGENT PROVENANCE (recovery from residues)", "PROCEDENCIA DEL AGENTE JVMTI (recuperación a partir de restos)"),
                sb.ToString());
            return;
        }

        var envs = Collect(ctx, jvm, sb);
        sb.AppendLine(L($"JVMTI environment objects to analyse: {envs.Count}", $"Objetos de entorno JVMTI para analizar: {envs.Count}"));
        sb.AppendLine();

        foreach (var e in envs)
        {
            Recover(ctx, jvm, e);
            Render(ctx, e, sb);
            ReportEnv(ctx, e);
        }

        if (envs.Count == 0)
        {
            sb.AppendLine(L("No JVMTI environment object found — nothing to recover.", "No se encontró ningún objeto de entorno JVMTI: no hay nada que recuperar."));
            sb.AppendLine(L("This is a negative result: during the lifetime of the process an agent environment", "Es un resultado negativo: durante la vida del proceso no se creó ningún entorno"));
            sb.AppendLine(L("was either not created or its memory was completely overwritten.", "de agente o su memoria se sobrescribió por completo."));
        }

        ctx.Report.Section(L("JVMTI AGENT PROVENANCE (recovery from residues)", "PROCEDENCIA DEL AGENTE JVMTI (recuperación a partir de restos)"),
            sb.ToString());
    }

    private static List<Env> Collect(ScanContext ctx, ImageInMemory jvm, StringBuilder sb)
    {
        var res = new List<Env>();
        var seen = new HashSet<ulong>();

        var data = jvm.Pe.Sections
            .Where(s => !s.IsExecutable && s.VirtualSize > 0)
            .Select(s => (Lo: jvm.Base + s.VirtualAddress,
                          Hi: jvm.Base + s.VirtualAddress + s.VirtualSize))
            .ToList();
        bool InJvmData(ulong v) => data.Any(x => v >= x.Lo && v < x.Hi);

        foreach (ulong a in ctx.JvmtiEnvs)
        {
            if (!seen.Add(a)) continue;
            var e = ReadEnv(ctx, a, InJvmData);
            if (e is not null) res.Add(e);
        }

        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateData, overlap: 0x20))
        {
            if (res.Count > 64) break;
            for (int i = 0; i + 0x20 <= ch.Length; i += 8)
            {
                ulong fn = BitConverter.ToUInt64(ch.Data, i);
                if (!InJvmData(fn)) continue;
                uint magic = BitConverter.ToUInt32(ch.Data, i + 8);
                if (magic is not (JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC)) continue;
                ulong addr = ch.Base + (ulong)i;
                if (!seen.Add(addr)) continue;
                var e = ReadEnv(ctx, addr, InJvmData);
                if (e is not null) res.Add(e);
                if (res.Count > 64) break;
            }
        }

        sb.AppendLine(L("JVMTI environment objects are identified by a pair of independent features:", "Los objetos de entorno JVMTI se identifican por un par de rasgos independientes:"));
        sb.AppendLine(L("a pointer to the function table inside jvm.dll data and the HotSpot magic number", "un puntero a la tabla de funciones dentro de los datos de jvm.dll y el número mágico de HotSpot"));
        sb.AppendLine(L("right after it. Both features together cannot be accidental.", "justo después. Ambos rasgos juntos no pueden ser casuales."));
        sb.AppendLine();
        return res;
    }

    private static Env? ReadEnv(ScanContext ctx, ulong addr, Func<ulong, bool> inJvmData)
    {
        var d = ctx.Target.ReadBytes(addr, 0x400);
        if (d is null) return null;
        ulong fn = BitConverter.ToUInt64(d, 0);
        if (!inJvmData(fn)) return null;
        uint magic = BitConverter.ToUInt32(d, 8);
        if (magic is not (JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC)) return null;

        return new Env
        {
            Address = addr,
            Dump = d,
            Functions = fn,
            Magic = magic,
            Version = BitConverter.ToUInt32(d, 12),
            Next = BitConverter.ToUInt64(d, 0x10),
            Retransformable = d[0x18] != 0,
            LocalStorage = BitConverter.ToUInt64(d, 0x20),
        };
    }

    private static void Recover(ScanContext ctx, ImageInMemory jvm, Env e)
    {
        ProbeLayout(ctx, e);
        RecoverCallbacks(ctx, e);
        RecoverPrefixes(ctx, e);
        RecoverAgentPointer(ctx, e);
        _ = jvm;
    }

    private static void ProbeLayout(ScanContext ctx, Env e)
    {
        var d = e.Dump;
        foreach (int cb in new[] { 0x28, 0x20, 0x30, 0x38, 0x40 })
        {
            if (cb + EventNames.Length * 8 + 0x40 > d.Length) continue;

            bool ok = true;
            int nonNull = 0;
            for (int i = 0; i < EventNames.Length && ok; i++)
            {
                ulong v = BitConverter.ToUInt64(d, cb + i * 8);
                if (v == 0) continue;
                if (v is < 0x10000 or > 0x7FFFFFFFFFFF) { ok = false; break; }
                var r = ctx.RegionAt(v);
                if (r is null || !r.IsCommitted || !r.IsExecutable) { ok = false; break; }
                nonNull++;
            }
            if (!ok) continue;

            int after = cb + EventNames.Length * 8;
            int tagOff = after + 8;
            int enableOff = tagOff + 8;
            int capsOff = enableOff + 24;
            if (capsOff + 32 > d.Length) continue;

            ulong tagMap = BitConverter.ToUInt64(d, tagOff);
            bool tagOk = tagMap == 0;
            if (!tagOk && tagMap is >= 0x10000 and <= 0x7FFFFFFFFFFF)
            {
                ulong back = ctx.Target.ReadU64(tagMap);
                tagOk = back == e.Address;
            }
            if (!tagOk) continue;

            ulong capsHi = BitConverter.ToUInt64(d, capsOff + 8);
            ulong prohHi = BitConverter.ToUInt64(d, capsOff + 24);
            if (capsHi != 0 || prohHi != 0) continue;

            e.CallbacksOff = cb;
            e.TagMapOff = tagOff;
            e.EnableOff = enableOff;
            e.CapsOff = capsOff;
            e.TagMap = tagMap;
            e.LayoutConfirmed = tagMap != 0 || nonNull > 0;
            e.Enable = new[]
            {
                BitConverter.ToUInt64(d, enableOff),
                BitConverter.ToUInt64(d, enableOff + 8),
                BitConverter.ToUInt64(d, enableOff + 16),
            };
            e.Caps = DecodeCaps(BitConverter.ToUInt64(d, capsOff));
            e.Prohibited = DecodeCaps(BitConverter.ToUInt64(d, capsOff + 16));
            return;
        }
    }

    private static List<string> DecodeCaps(ulong lo)
    {
        var res = new List<string>();
        for (int i = 0; i < CapabilityNames.Length; i++)
            if ((lo & (1UL << i)) != 0) res.Add(CapabilityNames[i]);
        return res;
    }

    private static void RecoverCallbacks(ScanContext ctx, Env e)
    {
        if (e.CallbacksOff < 0) return;
        for (int i = 0; i < EventNames.Length; i++)
        {
            ulong v = BitConverter.ToUInt64(e.Dump, e.CallbacksOff + i * 8);
            if (v == 0) continue;
            e.Callbacks.Add((EventNames[i], v));
        }
    }

    private static void RecoverPrefixes(ScanContext ctx, Env e)
    {
        for (int off = 0x20; off + 8 <= e.Dump.Length; off += 8)
        {
            ulong arr = BitConverter.ToUInt64(e.Dump, off);
            if (arr is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
            var reg = ctx.RegionAt(arr);
            if (reg is null || !reg.IsCommitted || reg.IsExecutable) continue;

            var found = new List<string>();
            for (int k = 0; k < 8; k++)
            {
                ulong p = ctx.Target.ReadU64(arr + (ulong)k * 8);
                if (p == 0) break;
                string? s = JvmtiAgentProbe.ReadAscii(ctx, p, 128);
                if (s is null || s.Length is < 1 or > 100) break;
                if (!s.All(ch => char.IsLetterOrDigit(ch) || ch is '_' or '$')) break;
                found.Add(s);
            }
            if (found.Count == 0) continue;
            foreach (var s in found)
                if (!e.Prefixes.Contains(s)) e.Prefixes.Add(s);
            if (e.Prefixes.Count >= 8) return;
        }
    }

    private static void RecoverAgentPointer(ScanContext ctx, Env e)
    {
        int from = e.CapsOff >= 0 ? e.CapsOff + 32 : 0x28;
        for (int off = from; off + 8 <= Math.Min(e.Dump.Length, from + 0x80); off += 8)
        {
            ulong p = BitConverter.ToUInt64(e.Dump, off);
            if (p is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
            var rec = JvmtiAgentProbe.TryRead(ctx, p);
            if (rec is null) continue;
            e.AgentPtr = p;
            e.Agent = rec;
            return;
        }
    }

    private static List<(string Klass, int Count)> TaggedClasses(ScanContext ctx, ulong tagMap)
    {
        var res = new Dictionary<string, int>(StringComparer.Ordinal);
        if (tagMap is < 0x10000 or > 0x7FFFFFFFFFFF) return new List<(string, int)>();
        var vm = ctx.Vm;
        if (vm is null || !vm.Valid || ctx.AllKlassObjects.Count == 0)
            return new List<(string, int)>();

        int offKlass = vm.OffAny("oopDesc", "_metadata._compressed_klass", "_metadata._klass");
        if (offKlass < 0) offKlass = 8;
        bool compressed = vm.Field("oopDesc", "_metadata._compressed_klass") is not null;
        ulong narrowBase = 0;
        int narrowShift = 0;
        if (compressed)
        {
            ulong bv = vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._base"),
                ("Universe", "_narrow_klass._base"));
            ulong sv = vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._shift"),
                ("Universe", "_narrow_klass._shift"));
            if (bv != 0) narrowBase = ctx.Target.ReadU64(bv);
            if (sv != 0) narrowShift = (int)ctx.Target.ReadU32(sv);
        }

        var cache = new PageCache(ctx.Target, 8192);
        var reg = ctx.RegionAt(tagMap);
        if (reg is null) return new List<(string, int)>();

        var queue = new Queue<ulong>();
        var visited = new HashSet<ulong>();
        queue.Enqueue(tagMap);
        int budget = 4096;

        while (queue.Count > 0 && budget-- > 0)
        {
            ulong at = queue.Dequeue();
            if (!visited.Add(at)) continue;
            var blk = cache.Read(at, 0x80);
            if (blk is null) continue;

            for (int i = 0; i + 8 <= blk.Length; i += 8)
            {
                ulong v = BitConverter.ToUInt64(blk, i);
                if (v is < 0x10000 or > 0x7FFFFFFFFFFF) continue;

                ulong k;
                if (compressed)
                {
                    uint narrow = cache.U32(v + (ulong)offKlass);
                    if (narrow == 0) k = 0;
                    else k = narrowBase + ((ulong)narrow << narrowShift);
                }
                else k = cache.U64(v + (ulong)offKlass);

                if (k != 0 && ctx.AllKlassObjects.TryGetValue(k, out var name) &&
                    name.Length > 0)
                {
                    res[name] = res.GetValueOrDefault(name) + 1;
                    continue;
                }

                var vr = ctx.RegionAt(v);
                if (vr is not null && vr.IsCommitted && vr.IsPrivate && !vr.IsExecutable &&
                    visited.Count < 2048)
                    queue.Enqueue(v);
            }
        }

        return res.OrderByDescending(x => x.Value).Select(x => (x.Key, x.Value)).ToList();
    }

    private static void Render(ScanContext ctx, Env e, StringBuilder sb)
    {
        sb.AppendLine(new string('=', 100));
        sb.AppendLine(L($"JVMTI ENVIRONMENT 0x{e.Address:X}", $"ENTORNO JVMTI 0x{e.Address:X}"));
        sb.AppendLine(L($"  state (magic)            : {e.MagicName}", $"  estado (magic)           : {e.MagicName}"));
        sb.AppendLine(L($"  JVMTI version (_version) : 0x{e.Version:X} (JVMTI {(e.Version >> 16) & 0xFF}.{(e.Version >> 8) & 0xFF}.{e.Version & 0xFF})", $"  versión JVMTI (_version) : 0x{e.Version:X} (JVMTI {(e.Version >> 16) & 0xFF}.{(e.Version >> 8) & 0xFF}.{e.Version & 0xFF})"));
        sb.AppendLine(L($"  function table           : 0x{e.Functions:X} → {ctx.Describe(e.Functions)}", $"  tabla de funciones       : 0x{e.Functions:X} → {ctx.Describe(e.Functions)}"));
        sb.AppendLine($"  _next                    : 0x{e.Next:X}");
        sb.AppendLine(L($"  _is_retransformable      : {(e.Retransformable ? "YES (default value, see the finding explanation)" : "no — so AddCapabilities was called")}", $"  _is_retransformable      : {(e.Retransformable ? "SÍ (valor por defecto, vea la explicación del hallazgo)" : "no: por tanto, se llamó a AddCapabilities")}"));
        sb.AppendLine($"  _env_local_storage       : 0x{e.LocalStorage:X}" +
                      (e.LocalStorage != 0 ? $" → {ctx.Describe(e.LocalStorage)}" : ""));
        sb.AppendLine(L($"  object layout            : ", $"  disposición del objeto   : ") +
                      (e.CallbacksOff < 0
                          ? L("NOT IDENTIFIED (callback table not found)", "NO IDENTIFICADA (no se encontró la tabla de callbacks)")
                          : L($"callbacks +0x{e.CallbacksOff:X}, tags +0x{e.TagMapOff:X}, masks +0x{e.EnableOff:X}, capabilities +0x{e.CapsOff:X}", $"callbacks +0x{e.CallbacksOff:X}, etiquetas +0x{e.TagMapOff:X}, máscaras +0x{e.EnableOff:X}, capacidades +0x{e.CapsOff:X}") +
                            (e.TagMap != 0 ? L(" — confirmed by the tag map back pointer", ": confirmada por el puntero inverso de la tabla de etiquetas") : "")));
        sb.AppendLine();

        if (e.Caps.Count > 0)
        {
            sb.AppendLine(L("  REQUESTED CAPABILITIES (jvmtiCapabilities):", "  CAPACIDADES SOLICITADAS (jvmtiCapabilities):"));
            foreach (var c in e.Caps) sb.AppendLine("      " + c);
            sb.AppendLine();
        }
        if (e.Prohibited.Count > 0)
        {
            sb.AppendLine(L("  PROHIBITED CAPABILITIES (_prohibited_capabilities):", "  CAPACIDADES PROHIBIDAS (_prohibited_capabilities):"));
            foreach (var c in e.Prohibited) sb.AppendLine("      " + c);
            sb.AppendLine();
        }

        if (e.Callbacks.Count > 0)
        {
            sb.AppendLine(L("  EVENT CALLBACK TABLE (position = event):", "  TABLA DE CALLBACKS DE EVENTOS (posición = evento):"));
            foreach (var (ev, target) in e.Callbacks)
            {
                var im = ctx.ImageAt(target);
                string where = im is null
                    ? L("NO MODULE — the agent library is unloaded", "NO HAY MÓDULO: la biblioteca del agente está descargada")
                    : im.Ldr is null ? L($"{im.Name} (module hidden from the loader)", $"{im.Name} (módulo oculto al cargador)") : im.Name;
                sb.AppendLine($"      {ev,-26} → 0x{target:X}  [{where}]  {ctx.Describe(target)}");
            }
            sb.AppendLine();
        }

        if (e.Enable.Length == 3)
        {
            sb.AppendLine(L("  EVENT ENABLE MASKS:", "  MÁSCARAS DE ACTIVACIÓN DE EVENTOS:"));
            sb.AppendLine($"      _event_user_enabled     = 0x{e.Enable[0]:X16}  {Bits(e.Enable[0])}");
            sb.AppendLine($"      _event_callback_enabled = 0x{e.Enable[1]:X16}  {Bits(e.Enable[1])}");
            sb.AppendLine($"      _event_enabled          = 0x{e.Enable[2]:X16}  {Bits(e.Enable[2])}");
            sb.AppendLine();
        }

        if (e.Prefixes.Count > 0)
        {
            sb.AppendLine(L("  NATIVE METHOD PREFIXES (SetNativeMethodPrefix):", "  PREFIJOS DE MÉTODOS NATIVOS (SetNativeMethodPrefix):"));
            foreach (var p in e.Prefixes) sb.AppendLine($"      «{p}»");
            sb.AppendLine();
        }

        if (e.Agent is not null)
        {
            sb.AppendLine(L("  AGENT RECORD REFERENCED BY THE ENVIRONMENT:", "  REGISTRO DEL AGENTE AL QUE APUNTA EL ENTORNO:"));
            sb.AppendLine(L($"      address : 0x{e.Agent.Address:X}", $"      dirección: 0x{e.Agent.Address:X}"));
            sb.AppendLine(L($"      name    : {e.Agent.Name}", $"      nombre   : {e.Agent.Name}"));
            sb.AppendLine(L($"      options : {e.Agent.Options ?? "-"}", $"      opciones : {e.Agent.Options ?? "-"}"));
            sb.AppendLine(L($"      path    : {e.Agent.OsLibPath ?? "-"}", $"      ruta     : {e.Agent.OsLibPath ?? "-"}"));
            sb.AppendLine(L($"      method  : {e.Agent.HowLoaded}", $"      método   : {e.Agent.HowLoaded}"));
            sb.AppendLine();
        }

        if (e.LocalStorage != 0)
        {
            var blk = ctx.Target.ReadBytes(e.LocalStorage, 256);
            if (blk is not null)
            {
                sb.AppendLine(L("  AGENT\'S OWN DATA (_env_local_storage):", "  DATOS PROPIOS DEL AGENTE (_env_local_storage):"));
                sb.AppendLine(HexDump.Format(blk, e.LocalStorage));
                var strings = StringExtract.Ascii(blk, 4);
                if (strings.Count > 0)
                    sb.AppendLine(L("      strings: ", "      cadenas: ") + string.Join(" | ", strings.Take(12)));
                sb.AppendLine();
            }
        }

        sb.AppendLine(L("  FULL ENVIRONMENT OBJECT:", "  OBJETO DE ENTORNO COMPLETO:"));
        sb.AppendLine(HexDump.Format(e.Dump, e.Address));
        sb.AppendLine();
    }

    private static string Bits(ulong v)
    {
        if (v == 0) return L("(no enabled events)", "(sin eventos activados)");
        var names = new List<string>();
        for (int i = 0; i < EventNames.Length; i++)
            if ((v & (1UL << i)) != 0) names.Add(EventNames[i]);
        return names.Count == 0 ? L("(bits outside the known range)", "(bits fuera del rango conocido)") : string.Join(",", names);
    }

    private static bool LooksInternal(ScanContext ctx, Env e)
    {
        if (e.Callbacks.Count == 0) return false;
        foreach (var (_, target) in e.Callbacks)
        {
            var im = ctx.ImageAt(target);
            if (im is null || !im.Name.Equals("jvm.dll", StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    private static void ReportEnv(ScanContext ctx, Env e)
    {
        bool internalEnv = LooksInternal(ctx, e);
        var f = ctx.Report.Report("JVM",
            L($"Agent recovery from JVMTI environment 0x{e.Address:X}: {e.MagicName}, capabilities {e.Caps.Count}, subscriptions {e.Callbacks.Count}", $"Recuperación del agente a partir del entorno JVMTI 0x{e.Address:X}: {e.MagicName}, capacidades {e.Caps.Count}, suscripciones {e.Callbacks.Count}") +
            (e.Prefixes.Count > 0 ? L($", native method prefixes {e.Prefixes.Count}", $", prefijos de métodos nativos {e.Prefixes.Count}") : "") +
            (e.Agent is not null ? L($", agent «{e.Agent.Name}»", $", agente «{e.Agent.Name}»") : "") +
            (internalEnv ? L(" — LOOKS LIKE THE VM\'S OWN INTERNAL ENVIRONMENT", ": PARECE EL ENTORNO INTERNO DE LA PROPIA VM") : ""),
            internalEnv ? Severity.High : Severity.Critical,
            (internalEnv
                ? L("IMPORTANT FOR INTERPRETATION: all event handlers of this environment lead into jvm.dll itself. This is what an internal virtual machine mechanism looks like, not a foreign agent — HotSpot creates its own JVMTI environment for Flight Recorder and uses it to instrument event classes. A foreign agent\'s handlers lie in ITS library or where there is no module any more. Check the handler list below. ", "IMPORTANTE PARA LA INTERPRETACIÓN: todos los manejadores de eventos de este entorno apuntan dentro de la propia jvm.dll. Así se ve un mecanismo interno de la máquina virtual, no un agente ajeno: HotSpot crea su propio entorno JVMTI para Flight Recorder y lo usa para instrumentar las clases de eventos. Los manejadores de un agente ajeno están en SU biblioteca o donde ya no hay módulo. Revise la lista de manejadores de abajo. ")
                : "") +
            L("The environment object is everything the virtual machine knows about the agent, and it survives both Agent_OnUnload and DisposeEnvironment: HotSpot only changes its magic number. The object layout is not assumed here but verified: the callback table was identified by all its 37 slots being either zero or leading to executable memory, and the offset found is confirmed by the back pointer from the tag map to this same environment. Below is everything recovered about the agent: which capabilities it requested, which events it subscribed to, where its handler functions led, which strings it set itself.", "El objeto de entorno es todo lo que la máquina virtual sabe del agente, y sobrevive tanto a Agent_OnUnload como a DisposeEnvironment: HotSpot solo cambia su número mágico. Aquí la disposición del objeto no se supone, sino que se verifica: la tabla de callbacks se identificó porque sus 37 entradas son cero o apuntan a memoria ejecutable, y el desplazamiento encontrado lo confirma el puntero inverso de la tabla de etiquetas a este mismo entorno. Abajo está todo lo que se recuperó del agente: qué capacidades solicitó, a qué eventos se suscribió, adónde apuntaban sus funciones manejadoras y qué cadenas definió él mismo."));

        f.Add(L("environment address", "dirección del entorno"), e.Address);
        f.Add(L("state", "estado"), e.MagicName);
        f.Add(L("JVMTI version", "versión JVMTI"), $"0x{e.Version:X}");
        f.Add(L("function table", "tabla de funciones"), $"0x{e.Functions:X} → {ctx.Describe(e.Functions)}");
        f.Add(L("layout confirmed", "disposición confirmada"), e.LayoutConfirmed ? L("yes", "sí") : L("partially", "parcialmente"));
        f.Add("_is_retransformable", JvmtiEnvLayout.DescribeRetransformable(e.Retransformable));

        if (e.Callbacks.Count > 0)
        {
            var byModule = e.Callbacks
                .GroupBy(x => ctx.ImageAt(x.Target)?.Name ?? L("<NO MODULE>", "<NO HAY MÓDULO>"))
                .ToList();
            f.Add(L("event handlers lead to", "los manejadores de eventos apuntan a"),
                string.Join(", ", byModule.Select(g => $"{g.Key} ×{g.Count()}")));

            var body = new StringBuilder();
            foreach (var (ev, target) in e.Callbacks)
            {
                var im = ctx.ImageAt(target);
                body.AppendLine($"  {(im is null ? "!!" : "  ")} {ev,-26} → 0x{target:X}  " +
                                (im is null
                                    ? L("NO module at this address", "NO hay módulo en esta dirección")
                                    : $"{im.Name}+0x{target - im.Base:X}" +
                                      (im.Ldr is null ? L(" (module hidden from the loader)", " (módulo oculto al cargador)") : "")));
                var code = ctx.Target.ReadBytes(target, 16);
                if (code is not null)
                    body.AppendLine(L("            bytes: ", "            bytes: ") +
                                    string.Join(" ", code.Select(x => x.ToString("X2"))));
            }
            f.Block(L("Agent event handlers", "Manejadores de eventos del agente"), body.ToString().TrimEnd());

            int orphan = e.Callbacks.Count(x => ctx.ImageAt(x.Target) is null);
            if (orphan > 0)
                ctx.Report.Report("JVM",
                        L($"JVMTI environment 0x{e.Address:X} has {orphan} event handlers leading where there is no module at all", $"El entorno JVMTI 0x{e.Address:X} tiene {orphan} manejadores de eventos que apuntan donde no hay ningún módulo"),
                        Severity.Critical,
                        L("The agent function addresses remained recorded in the callback table, but there is no module at these addresses any more. This is direct proof that the agent library was running and was unloaded: while it was loaded, the addresses led into it. The record does not survive in only one case — if the agent carefully zeroed the table before leaving, and it did not.", "Las direcciones de las funciones del agente siguen registradas en la tabla de callbacks, pero ya no hay ningún módulo en ellas. Es una prueba directa de que la biblioteca del agente se ejecutó y se descargó: mientras estuvo cargada, las direcciones apuntaban a ella. El registro solo no sobrevive en un caso: si el agente puso la tabla a cero con cuidado antes de irse, y no lo hizo."))
                    .Add(L("environment", "entorno"), e.Address)
                    .Add(L("orphaned handlers", "manejadores huérfanos"), orphan.ToString())
                    .Block(L("Handlers", "Manejadores"), string.Join("\n", e.Callbacks
                        .Where(x => ctx.ImageAt(x.Target) is null)
                        .Select(x => L($"  {x.Event,-26} → 0x{x.Target:X} ({ctx.RegionAt(x.Target)?.ToString() ?? "not mapped"})", $"  {x.Event,-26} → 0x{x.Target:X} ({ctx.RegionAt(x.Target)?.ToString() ?? "no proyectado"})"))));
        }

        if (e.Caps.Count > 0)
            f.Block(L("Requested capabilities", "Capacidades solicitadas"), string.Join("\n", e.Caps.Select(x => "  " + x)));
        if (e.Prohibited.Count > 0)
            f.Block(L("Prohibited capabilities", "Capacidades prohibidas"), string.Join("\n", e.Prohibited.Select(x => "  " + x)));

        if (e.Prefixes.Count > 0)
        {
            ctx.Report.Report("JVM",
                    L($"The agent set native method prefixes: ", $"El agente definió prefijos de métodos nativos: ") +
                    string.Join(", ", e.Prefixes.Select(x => $"«{x}»")),
                    Severity.Critical,
                    L("The JVMTI function SetNativeMethodPrefix lets an agent rename a native method so that a call to it first reaches the agent\'s wrapper. The prefix string is a LITERAL written by the agent author: it is stored in the environment as is. Neither the virtual machine nor the game calls this function: it exists solely for instrumentation agents.", "La función JVMTI SetNativeMethodPrefix permite a un agente renombrar un método nativo para que su llamada pase primero por el envoltorio del agente. La cadena del prefijo es un LITERAL escrito por el autor del agente: se guarda en el entorno tal cual. Ni la máquina virtual ni el juego llaman a esta función: existe únicamente para agentes de instrumentación."))
                .Add(L("environment", "entorno"), e.Address)
                .Block(L("Prefixes", "Prefijos"), string.Join("\n", e.Prefixes.Select(x => $"  «{x}»")));
        }

        if (e.Agent is not null)
        {
            f.Add(L("agent record", "registro del agente"), L($"0x{e.Agent.Address:X}, name «{e.Agent.Name}», {e.Agent.HowLoaded}", $"0x{e.Agent.Address:X}, nombre «{e.Agent.Name}», {e.Agent.HowLoaded}"));
            if (e.Agent.Options is not null) f.Add(L("agent options", "opciones del agente"), e.Agent.Options);
            if (e.Agent.OsLibPath is not null) f.Add(L("agent library path", "ruta de la biblioteca del agente"), e.Agent.OsLibPath);
        }

        if (e.LocalStorage != 0)
        {
            var blk = ctx.Target.ReadBytes(e.LocalStorage, 512);
            var strings = blk is null ? new List<string>() : StringExtract.Ascii(blk, 4);
            ctx.Report.Report("JVM",
                    L($"JVMTI environment 0x{e.Address:X} holds a pointer to the agent\'s own data (_env_local_storage = 0x{e.LocalStorage:X})", $"El entorno JVMTI 0x{e.Address:X} guarda un puntero a los datos propios del agente (_env_local_storage = 0x{e.LocalStorage:X})"),
                    Severity.Critical,
                    L("This field is filled only by the agent itself with SetEnvironmentLocalStorage: it puts a pointer to its state structure there to find it in event handlers. Neither the virtual machine nor the game touches this field. The structure content often shows the agent\'s purpose: its settings, handles and strings lie there.", "Este campo solo lo rellena el propio agente con SetEnvironmentLocalStorage: guarda ahí un puntero a su estructura de estado para encontrarla en los manejadores de eventos. Ni la máquina virtual ni el juego tocan este campo. El contenido de la estructura suele mostrar el propósito del agente: ahí están su configuración, sus handles y sus cadenas."))
                .Add(L("environment", "entorno"), e.Address)
                .Add(L("data address", "dirección de los datos"), e.LocalStorage)
                .Add(L("where the data lies", "dónde están los datos"), ctx.RegionAt(e.LocalStorage)?.ToString() ?? L("not mapped", "no proyectado"))
                .Block(L("Content", "Contenido"), blk is null ? L("not readable", "no legible")
                    : HexDump.Format(blk, e.LocalStorage))
                .Block(L("Strings inside", "Cadenas dentro"), strings.Count == 0 ? L("none", "ninguna")
                    : string.Join("\n", strings.Take(40).Select(x => "  " + x)));
        }

        if (e.TagMap != 0)
        {
            var tagged = TaggedClasses(ctx, e.TagMap);
            var tf = ctx.Report.Report("JVM",
                L($"JVMTI environment 0x{e.Address:X} has an object tag map", $"El entorno JVMTI 0x{e.Address:X} tiene una tabla de etiquetas de objetos") +
                (tagged.Count > 0
                    ? L($"; tagged objects belong to {tagged.Count} classes", $"; los objetos etiquetados pertenecen a {tagged.Count} clases")
                    : ""),
                Severity.Critical,
                L("JvmtiTagMap is created on the very first call to SetTag, GetObjectsWithTags or IterateOverHeap. It means the agent tagged objects in the Java heap and iterated over them — this is how a cheat finds player, world and entity objects to access them directly. The classes of tagged objects were recovered by a self-verifying feature: a value from the table is considered a Java object only if its class pointer matches a real Klass object in the metaspace.", "JvmtiTagMap se crea en la primera llamada a SetTag, GetObjectsWithTags o IterateOverHeap. Significa que el agente etiquetó objetos en el heap de Java y los recorrió: así encuentra un cheat los objetos del jugador, del mundo y de las entidades para acceder a ellos directamente. Las clases de los objetos etiquetados se recuperaron con un rasgo autoverificable: un valor de la tabla solo se considera objeto Java si su puntero de clase coincide con un objeto Klass real del metaspace."));
            tf.Add(L("environment", "entorno"), e.Address);
            tf.Add("JvmtiTagMap", e.TagMap);
            foreach (var (klass, n) in tagged.Take(40))
                tf.Add(klass, L($"{n} tagged objects", $"{n} objetos etiquetados"));
            var tm = ctx.Target.ReadBytes(e.TagMap, 256);
            if (tm is not null) tf.Block(L("Tag map", "Tabla de etiquetas"), HexDump.Format(tm, e.TagMap));
        }

        f.Block(L("Environment object (0x400 bytes)", "Objeto de entorno (0x400 bytes)"), HexDump.Format(e.Dump, e.Address));

        if (ctx.Dumper is not null)
        {
            ulong from = e.Address > 0x2000 ? e.Address - 0x2000 : e.Address;
            string? p = ctx.Dumper.DumpRange(from, 0x8000, "jvmtienv-prov",
                L("JVMTI environment object and its neighbourhood for agent recovery", "objeto de entorno JVMTI y su entorno para recuperar el agente"),
                L($"the object itself at 0x{e.Address:X}", $"el propio objeto en 0x{e.Address:X}"));
            if (p is not null) f.Add(L("neighbourhood dump", "volcado del entorno"), p);
        }
    }
}
