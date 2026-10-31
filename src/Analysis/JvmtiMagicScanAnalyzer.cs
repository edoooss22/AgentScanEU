using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JvmtiMagicScanAnalyzer
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

    private sealed class Hit
    {
        public ulong Address;
        public uint Magic, Version;
        public ulong Functions;
        public ulong Next;
        public ulong TagMap;
        public bool TagMapConfirmed;
        public bool FunctionsValid;
        public int CallbacksOff = -1;
        public int NonNullCallbacks;
        public List<string> Subscriptions = new();
        public List<string> Caps = new();
        public int Score;
        public List<string> Checks = new();
        public byte[]? Dump;

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

        sb.AppendLine(L("Search for JVMTI environment objects by the HotSpot magic number, without relying", "Búsqueda de objetos de entorno JVMTI por el número mágico de HotSpot, sin depender"));
        sb.AppendLine(L("on the function table pointer. The other checks identify an environment exactly", "del puntero a la tabla de funciones. Las demás comprobaciones identifican el entorno justamente"));
        sb.AppendLine(L("by this pointer, so wiping it blinds them all at once; here", "por ese puntero, así que borrarlo las ciega a todas a la vez; aquí"));
        sb.AppendLine(L("the marker is different, and confidence is built from independent checks.", "el indicador es otro y la fiabilidad se obtiene de comprobaciones independientes."));
        sb.AppendLine();

        var known = ctx.JvmtiEnvs.ToHashSet();
        var hits = Scan(ctx, jvm, sb);

        sb.AppendLine(L($"Magic number matches that passed verification: {hits.Count}", $"Coincidencias del número mágico que pasaron la verificación: {hits.Count}"));
        sb.AppendLine(L($"Already found by the other checks: {hits.Count(h => known.Contains(h.Address))}", $"Ya encontradas por las demás comprobaciones: {hits.Count(h => known.Contains(h.Address))}"));
        sb.AppendLine();

        foreach (var h in hits)
        {
            Render(ctx, h, known.Contains(h.Address), sb);
            Report(ctx, h, known.Contains(h.Address));
        }

        if (hits.Count == 0)
            sb.AppendLine(L("No object resembling a JVMTI environment was found.", "No se encontró ningún objeto que parezca un entorno JVMTI."));

        ctx.Report.Section(L("JVMTI ENVIRONMENTS BY MAGIC NUMBER (independent search)", "ENTORNOS JVMTI POR NÚMERO MÁGICO (búsqueda independiente)"),
            sb.ToString());
    }

    private static List<Hit> Scan(ScanContext ctx, ImageInMemory? jvm, StringBuilder sb)
    {
        var res = new List<Hit>();
        var seen = new HashSet<ulong>();

        var data = jvm is { Pe.Valid: true }
            ? jvm.Pe.Sections.Where(s => !s.IsExecutable && s.VirtualSize > 0)
                  .Select(s => (Lo: jvm.Base + s.VirtualAddress,
                                Hi: jvm.Base + s.VirtualAddress + s.VirtualSize)).ToList()
            : new List<(ulong Lo, ulong Hi)>();
        bool InJvmData(ulong v) => data.Any(x => v >= x.Lo && v < x.Hi);

        long candidates = 0, rejected = 0;

        foreach (var ch in MemoryScan.Chunks(ctx, MemoryScan.PrivateData, overlap: 0x400))
        {
            for (int i = 8; i + 8 <= ch.Length; i += 8)
            {
                uint magic = BitConverter.ToUInt32(ch.Data, i);
                if (magic is not (JVMTI_MAGIC or DISPOSED_MAGIC or BAD_MAGIC)) continue;

                ulong addr = ch.Base + (ulong)i - 8;
                if (!seen.Add(addr)) continue;
                candidates++;

                var h = Validate(ctx, addr, magic, InJvmData);
                if (h is null) { rejected++; continue; }
                res.Add(h);
                if (res.Count >= 64) break;
            }
            if (res.Count >= 64) break;
        }

        sb.AppendLine(L($"Private memory scanned : ", $"Memoria privada revisada : ") +
                      MemoryAnalyzer.Human(MemoryScan.TotalReadable(ctx, MemoryScan.PrivateData)) +
                      L(" (no volume limit)", " (sin límite de volumen)"));
        sb.AppendLine(L($"Magic number matches   : {candidates}", $"Coincidencias del número mágico : {candidates}"));
        sb.AppendLine(L($"Rejected by structure checks : {rejected}", $"Descartadas por comprobaciones de estructura : {rejected}"));
        return res;
    }

    private static Hit? Validate(ScanContext ctx, ulong addr, uint magic,
        Func<ulong, bool> inJvmData)
    {
        var d = ctx.Target.ReadBytes(addr, 0x400);
        if (d is null) return null;

        var h = new Hit
        {
            Address = addr,
            Magic = magic,
            Functions = BitConverter.ToUInt64(d, 0),
            Version = BitConverter.ToUInt32(d, 12),
            Next = BitConverter.ToUInt64(d, 0x10),
            Dump = d,
        };

        if ((h.Version >> 24) != 0x30) return null;
        h.Score += 2;
        h.Checks.Add(L($"JVMTI version number 0x{h.Version:X8} is valid (JVMTI {(h.Version >> 16) & 0xFF}.{(h.Version >> 8) & 0xFF}.{h.Version & 0xFF})", $"el número de versión JVMTI 0x{h.Version:X8} es correcto (JVMTI {(h.Version >> 16) & 0xFF}.{(h.Version >> 8) & 0xFF}.{h.Version & 0xFF})"));

        if (h.Next != 0)
        {
            if (h.Next is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
            var nr = ctx.RegionAt(h.Next);
            if (nr is null || !nr.IsCommitted) return null;
            h.Score++;
            h.Checks.Add(L($"the _next field leads to committed memory (0x{h.Next:X})", $"el campo _next apunta a memoria comprometida (0x{h.Next:X})"));
        }
        else h.Checks.Add(L("the _next field is empty (single environment or end of the list)", "el campo _next está vacío (entorno único o final de la lista)"));

        if (inJvmData(h.Functions))
        {
            h.FunctionsValid = true;
            h.Score += 3;
            h.Checks.Add(L("the function table field is intact and leads to jvm.dll data — the other checks also see the object", "el campo de la tabla de funciones está intacto y apunta a los datos de jvm.dll: las demás comprobaciones también ven el objeto"));
        }
        else
            h.Checks.Add(h.Functions == 0
                ? L("the function table field is ZEROED — the other checks do not see such an object", "el campo de la tabla de funciones está PUESTO A CERO: las demás comprobaciones no ven este objeto")
                : L($"the function table field (0x{h.Functions:X}) does NOT lead to jvm.dll data — the other checks do not see such an object", $"el campo de la tabla de funciones (0x{h.Functions:X}) NO apunta a los datos de jvm.dll: las demás comprobaciones no ven este objeto"));

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
                var reg = ctx.RegionAt(v);
                if (reg is null || !reg.IsCommitted || !reg.IsExecutable) { ok = false; break; }
                nonNull++;
            }
            if (!ok) continue;

            int after = cb + EventNames.Length * 8;
            int tagOff = after + 8;
            int capsOff = tagOff + 8 + 24;
            if (capsOff + 32 > d.Length) continue;

            if (BitConverter.ToUInt64(d, capsOff + 8) != 0) continue;
            if (BitConverter.ToUInt64(d, capsOff + 24) != 0) continue;

            ulong tagMap = BitConverter.ToUInt64(d, tagOff);
            if (tagMap != 0)
            {
                if (tagMap is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
                if (ctx.Target.ReadU64(tagMap) == addr)
                {
                    h.TagMap = tagMap;
                    h.TagMapConfirmed = true;
                    h.Score += 4;
                    h.Checks.Add(L($"tag map 0x{tagMap:X} refers BACK to this environment — the layout is confirmed unambiguously", $"la tabla de etiquetas 0x{tagMap:X} apunta DE VUELTA a este entorno: la disposición se confirma sin ambigüedad"));
                }
                else h.TagMap = tagMap;
            }

            h.CallbacksOff = cb;
            h.NonNullCallbacks = nonNull;
            h.Score += nonNull > 0 ? 3 : 1;
            h.Checks.Add(nonNull > 0
                ? L($"callback table at +0x{cb:X}: {nonNull} handlers, all lead to executable memory", $"tabla de callbacks en +0x{cb:X}: {nonNull} manejadores, todos apuntan a memoria ejecutable")
                : L($"callback table at +0x{cb:X} is empty (the agent removed its handlers before leaving)", $"la tabla de callbacks en +0x{cb:X} está vacía (el agente quitó sus manejadores antes de irse)"));

            for (int i = 0; i < EventNames.Length; i++)
            {
                ulong v = BitConverter.ToUInt64(d, cb + i * 8);
                if (v != 0) h.Subscriptions.Add($"{EventNames[i]} → {ctx.Describe(v)}");
            }

            ulong caps = BitConverter.ToUInt64(d, capsOff);
            for (int i = 0; i < CapabilityNames.Length; i++)
                if ((caps & (1UL << i)) != 0) h.Caps.Add(CapabilityNames[i]);
            if (h.Caps.Count > 0) h.Score += 2;
            break;
        }

        if (h.CallbacksOff < 0 && !h.FunctionsValid) return null;
        return h.Score >= 5 ? h : null;
    }

    private static void Render(ScanContext ctx, Hit h, bool alreadyKnown, StringBuilder sb)
    {
        sb.AppendLine(new string('=', 100));
        sb.AppendLine(L($"CANDIDATE 0x{h.Address:X}  {h.MagicName}", $"CANDIDATO 0x{h.Address:X}  {h.MagicName}"));
        sb.AppendLine(L($"  confidence              : {h.Score} ", $"  fiabilidad              : {h.Score} ") +
                      (alreadyKnown ? L("(object already found by the other checks)", "(objeto ya encontrado por las demás comprobaciones)")
                                    : L("(NEW object — the other checks do not see it)", "(objeto NUEVO: las demás comprobaciones no lo ven)")));
        sb.AppendLine(L($"  function table field    : 0x{h.Functions:X} ", $"  campo tabla de funciones: 0x{h.Functions:X} ") +
                      (h.FunctionsValid ? L("(intact)", "(intacto)") : L("(WIPED or replaced)", "(BORRADO o sustituido)")));
        sb.AppendLine(L($"  JVMTI version           : 0x{h.Version:X8}", $"  versión JVMTI           : 0x{h.Version:X8}"));
        sb.AppendLine($"  _next                   : 0x{h.Next:X}");
        sb.AppendLine(L($"  tag map                 : ", $"  tabla de etiquetas      : ") +
                      (h.TagMap == 0 ? L("none", "no")
                        : $"0x{h.TagMap:X}" + (h.TagMapConfirmed ? L(" (confirmed)", " (confirmada)") : "")));
        sb.AppendLine(L($"  region                  : {ctx.RegionAt(h.Address)?.ToString() ?? "-"}", $"  región                  : {ctx.RegionAt(h.Address)?.ToString() ?? "-"}"));
        sb.AppendLine(L("  checks performed:", "  comprobaciones realizadas:"));
        foreach (var c in h.Checks) sb.AppendLine("      • " + c);
        if (h.Caps.Count > 0)
        {
            sb.AppendLine(L("  requested capabilities:", "  capacidades solicitadas:"));
            foreach (var c in h.Caps) sb.AppendLine("      " + c);
        }
        if (h.Subscriptions.Count > 0)
        {
            sb.AppendLine(L("  event subscriptions:", "  suscripciones a eventos:"));
            foreach (var s in h.Subscriptions) sb.AppendLine("      " + s);
        }
        if (h.Dump is not null) sb.AppendLine(HexDump.Format(h.Dump, h.Address));
        sb.AppendLine();
    }

    private static void Report(ScanContext ctx, Hit h, bool alreadyKnown)
    {
        Severity sev = h.FunctionsValid && alreadyKnown ? Severity.Info : Severity.Critical;

        var f = ctx.Report.Report("JVM",
            L($"Magic number search: JVMTI environment 0x{h.Address:X} — {h.MagicName}", $"Búsqueda por número mágico: entorno JVMTI 0x{h.Address:X} — {h.MagicName}") +
            (h.FunctionsValid ? "" : L(", function table field WIPED", ", campo de la tabla de funciones BORRADO")) +
            (alreadyKnown ? L(" (confirms what was already found)", " (confirma lo ya encontrado)") : L(" (the other checks did not see it)", " (las demás comprobaciones no lo vieron)")),
            sev,
            L("The object was found NOT by the function table pointer but by the HotSpot magic number inside it. This matters: all other environment checks identify the object by its first field, so wiping eight bytes hides it from all of them at once, although the object itself, with all its capabilities and subscriptions, stays in memory. ", "El objeto NO se encontró por el puntero a la tabla de funciones, sino por el número mágico de HotSpot que contiene. Esto importa: todas las demás comprobaciones de entornos identifican el objeto por su primer campo, así que borrar ocho bytes lo oculta de todas a la vez, aunque el propio objeto, con todas sus capacidades y suscripciones, sigue en memoria. ") +
            (h.FunctionsValid
                ? L("Here the field is intact, and the finding matches what the other checks found — so this is a cross-confirmation, not new evidence.", "Aquí el campo está intacto y el hallazgo coincide con lo que encontraron las demás comprobaciones: es una confirmación cruzada, no una prueba nueva.")
                : L("Here the field does NOT lead to jvm.dll data: it is either zeroed or replaced. That alone is already an anomaly — the virtual machine never changes this field. The object was identified by independent features: a valid JVMTI version number, a consistent _next field, a table of 37 handler slots, each either empty or leading to executable memory", "Aquí el campo NO apunta a los datos de jvm.dll: está puesto a cero o sustituido. Eso ya es una anomalía por sí solo: la máquina virtual nunca cambia este campo. El objeto se identificó por rasgos independientes: un número de versión JVMTI correcto, un campo _next coherente y una tabla de 37 entradas de manejadores, cada una vacía o apuntando a memoria ejecutable") +
                  (h.TagMapConfirmed
                      ? L(", and a tag map referring back to this same environment", ", y una tabla de etiquetas que apunta de vuelta a este mismo entorno")
                      : "") + "."));

        f.Add(L("object address", "dirección del objeto"), h.Address);
        f.Add(L("magic number", "número mágico"), h.MagicName);
        f.Add(L("JVMTI version", "versión JVMTI"), $"0x{h.Version:X8}");
        f.Add(L("function table field", "campo de la tabla de funciones"), h.FunctionsValid
            ? L($"0x{h.Functions:X} (intact)", $"0x{h.Functions:X} (intacto)")
            : L($"0x{h.Functions:X} — does NOT lead to jvm.dll data", $"0x{h.Functions:X}: NO apunta a los datos de jvm.dll"));
        f.Add(L("confidence score", "puntuación de fiabilidad"), h.Score.ToString());
        f.Add(L("found by the other checks", "encontrado por las demás comprobaciones"), alreadyKnown ? L("yes", "sí") : L("NO", "NO"));
        f.Add(L("event handlers", "manejadores de eventos"), h.NonNullCallbacks.ToString());
        f.Add(L("tag map", "tabla de etiquetas"), h.TagMap == 0 ? L("none", "no")
            : $"0x{h.TagMap:X}" + (h.TagMapConfirmed ? L(" (back reference confirmed)", " (referencia inversa confirmada)") : ""));
        f.Add(L("region", "región"), ctx.RegionAt(h.Address)?.ToString() ?? "-");

        f.Block(L("Checks performed", "Comprobaciones realizadas"), string.Join("\n", h.Checks.Select(x => "  • " + x)));
        if (h.Caps.Count > 0)
            f.Block(L("Requested capabilities", "Capacidades solicitadas"), string.Join("\n", h.Caps.Select(x => "  " + x)));
        if (h.Subscriptions.Count > 0)
            f.Block(L("Event subscriptions", "Suscripciones a eventos"), string.Join("\n", h.Subscriptions.Select(x => "  " + x)));
        if (h.Dump is not null)
            f.Block(L("Environment object (0x400 bytes)", "Objeto de entorno (0x400 bytes)"), HexDump.Format(h.Dump, h.Address));

        if (ctx.Dumper is not null && !alreadyKnown)
        {
            ulong from = h.Address > 0x1000 ? h.Address - 0x1000 : h.Address;
            string? p = ctx.Dumper.DumpRange(from, 0x4000, "jvmtienv-magic",
                L("JVMTI environment found by magic number", "entorno JVMTI encontrado por número mágico"),
                L($"the object itself at 0x{h.Address:X}, {h.MagicName}", $"el propio objeto en 0x{h.Address:X}, {h.MagicName}"));
            if (p is not null) f.Add(L("neighbourhood dump", "volcado del entorno"), p);
        }
    }
}
