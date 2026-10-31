using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JavaRuntimeStateAnalyzer
{
    public static void Run(ScanContext ctx)
    {
        var sb = new StringBuilder();
        sb.AppendLine(L("JAVA RUNTIME STATE", "ESTADO DEL ENTORNO DE EJECUCIÓN JAVA"));
        sb.AppendLine();

        var m = ctx.Java;
        int offMirror = ctx.Vm?.Off("Klass", "_java_mirror") ?? -1;
        if (m is null || offMirror < 0)
        {
            sb.AppendLine(L("  class map or static field access unavailable — check skipped.", "  mapa de clases o acceso a campos estáticos no disponibles: comprobación omitida."));
            ctx.Report.Section(L("JAVA RUNTIME", "ENTORNO DE EJECUCIÓN JAVA"), sb.ToString());
            return;
        }

        Properties(ctx, m, offMirror, sb);
        OpenedPackages(ctx, m, sb);
        NativeLibraries(ctx, m, sb);

        ctx.Report.Section(L("JAVA RUNTIME", "ENTORNO DE EJECUCIÓN JAVA"), sb.ToString());
    }

    private static void Properties(ScanContext ctx, JavaMeta m, int offMirror, StringBuilder sb)
    {
        sb.AppendLine(L("SYSTEM PROPERTIES: LIVE TABLE AND THE SNAPSHOT TAKEN AT STARTUP", "PROPIEDADES DEL SISTEMA: TABLA VIVA E INSTANTÁNEA TOMADA AL ARRANCAR"));
        sb.AppendLine();

        ulong liveObj = StaticOop(m, offMirror, "java/lang/System", "props");
        ulong savedObj = StaticOop(m, offMirror, "jdk/internal/misc/VM", "savedProps");

        var live = liveObj != 0 ? ReadMap(m, liveObj) : null;
        var saved = savedObj != 0 ? ReadMap(m, savedObj) : null;

        sb.AppendLine(L($"  live table java.lang.System.props          : 0x{liveObj:X}, read {(live?.Count.ToString() ?? "none")}", $"  tabla viva java.lang.System.props           : 0x{liveObj:X}, leídas {(live?.Count.ToString() ?? "ninguna")}"));
        sb.AppendLine(L($"  snapshot jdk.internal.misc.VM.savedProps    : 0x{savedObj:X}, read {(saved?.Count.ToString() ?? "none")}", $"  instantánea jdk.internal.misc.VM.savedProps : 0x{savedObj:X}, leídas {(saved?.Count.ToString() ?? "ninguna")}"));
        sb.AppendLine();

        if (live is null || live.Count == 0)
        {
            sb.AppendLine(L("  live property table not read — comparison not performed.", "  no se leyó la tabla viva de propiedades: no se hizo la comparación."));
            sb.AppendLine();
            return;
        }

        sb.AppendLine(L("  FULL LIVE TABLE", "  TABLA VIVA COMPLETA"));
        foreach (var kv in live.OrderBy(x => x.Key, StringComparer.Ordinal))
            sb.AppendLine($"      {kv.Key} = {JavaMeta.Clean(kv.Value, 400)}");
        sb.AppendLine();

        CheckAttachSelf(ctx, live);

        if (saved is null || saved.Count == 0)
        {
            sb.AppendLine(L("  property snapshot not read — nothing to compare the live table with.", "  no se leyó la instantánea de propiedades: no hay con qué comparar la tabla viva."));
            sb.AppendLine();
            return;
        }

        var added = live.Where(kv => !saved.ContainsKey(kv.Key)).ToList();
        var changed = live.Where(kv => saved.TryGetValue(kv.Key, out string? o) && o != kv.Value)
            .Select(kv => (kv.Key, Was: saved[kv.Key], Now: kv.Value)).ToList();
        var removed = saved.Keys.Where(k => !live.ContainsKey(k)).ToList();

        sb.AppendLine(L($"  appeared after startup : {added.Count}", $"  aparecidas tras el arranque : {added.Count}"));
        foreach (var kv in added.OrderBy(x => x.Key, StringComparer.Ordinal))
            sb.AppendLine($"      + {kv.Key} = {JavaMeta.Clean(kv.Value, 400)}");
        sb.AppendLine(L($"  changed after startup  : {changed.Count}", $"  cambiadas tras el arranque  : {changed.Count}"));
        foreach (var (k, was, now) in changed.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            sb.AppendLine($"      ~ {k}");
            sb.AppendLine(L($"           was: {JavaMeta.Clean(was, 400)}", $"           antes: {JavaMeta.Clean(was, 400)}"));
            sb.AppendLine(L($"           now: {JavaMeta.Clean(now, 400)}", $"           ahora: {JavaMeta.Clean(now, 400)}"));
        }
        sb.AppendLine(L($"  gone from the live table: {removed.Count}", $"  desaparecidas de la tabla viva: {removed.Count}"));
        foreach (string k in removed) sb.AppendLine($"      - {k}");
        sb.AppendLine();

        ReportRuntimeProps(ctx, added, changed, removed);
    }

    private static void CheckAttachSelf(ScanContext ctx, Dictionary<string, string> live)
    {
        string[] keys =
        {
            "jdk.attach.allowAttachSelf", "jdk.attach.allowPermissionsToAttachSelf",
        };
        foreach (string key in keys)
        {
            if (!live.TryGetValue(key, out string? v)) continue;
            bool on = v.Equals("true", StringComparison.OrdinalIgnoreCase) || v.Length == 0;
            ctx.Report.Report("JVM",
                L($"Property {key} = «{v}»", $"Propiedad {key} = «{v}»"),
                on ? Severity.Critical : Severity.Medium,
                L("This property allows the process to attach to its OWN virtual machine with the attach mechanism. By default it is not set at all, and a self-attach attempt is rejected. It is set precisely so that code already running inside the process can inject a JVMTI agent into it without a separate loader process. The game and its mods do not do this.", "Esta propiedad permite al proceso conectarse a su PROPIA máquina virtual con el mecanismo attach. Por defecto no está definida y un intento de autoconexión se rechaza. Se define justamente para que el código que ya se ejecuta dentro del proceso pueda inyectarle un agente JVMTI sin un proceso cargador aparte. El juego y sus mods no hacen esto."))
                .Add(L("property", "propiedad"), key)
                .Add(L("value", "valor"), v.Length == 0 ? L("<empty, which means «enabled»>", "<vacío, lo que significa «activado»>") : v);
        }
    }

    private static void ReportRuntimeProps(ScanContext ctx, List<KeyValuePair<string, string>> added,
        List<(string Key, string Was, string Now)> changed, List<string> removed)
    {
        bool Routine(string k) =>
            k.StartsWith("java.vm.", StringComparison.Ordinal) ||
            k.StartsWith("java.specification", StringComparison.Ordinal) ||
            k is "java.class.version" or "line.separator" or "java.io.tmpdir" or
                "user.timezone" or "java.vendor.url.bug" or "sun.font.fontmanager" or
                "java.awt.graphicsenv" or "awt.toolkit" or "sun.awt.enableExtraMouseButtons" or
                "java.awt.printerjob" or "sun.java2d.d3d";

        var interesting = added.Where(kv => !Routine(kv.Key)).ToList();
        if (interesting.Count > 0)
        {
            bool loud = interesting.Any(kv => AgentRelated(kv.Key) || AgentRelated(kv.Value));
            var f = ctx.Report.Report("JAVA",
                L($"{interesting.Count} system properties were set at runtime — they are not in the snapshot taken when the virtual machine started", $"{interesting.Count} propiedades del sistema se definieron durante la ejecución: no están en la instantánea tomada al arrancar la máquina virtual"),
                loud ? Severity.High : Severity.Info,
                L("The runtime keeps two copies of the property table: the live one, which can be changed with System.setProperty, and an immutable snapshot taken at VM startup before any application code ran. A property that is in the live table and missing from the snapshot was set by code that was already running. That is legitimate by itself — mods do it too — but the list must be explained: properties are exactly how agent loading, library paths and the behaviour of the attach mechanism are configured.", "El entorno de ejecución guarda dos copias de la tabla de propiedades: la viva, que puede cambiarse con System.setProperty, y una instantánea inmutable tomada al arrancar la máquina antes de ejecutar código de la aplicación. Una propiedad que está en la tabla viva y falta en la instantánea la definió código que ya se estaba ejecutando. Eso es legítimo por sí solo (los mods también lo hacen), pero la lista debe tener explicación: precisamente mediante propiedades se configuran la carga de agentes, las rutas de bibliotecas y el comportamiento del mecanismo attach."));
            foreach (var kv in interesting.Take(60))
                f.Add(kv.Key, JavaMeta.Clean(kv.Value, 300));
        }

        var keyChanged = changed.Where(x =>
            x.Key is "java.class.path" or "java.library.path" or "sun.boot.library.path" or
                "sun.java.command" or "java.home" or "user.dir" or "jdk.module.path" or
                "java.system.class.loader" or "java.protocol.handler.pkgs").ToList();
        if (keyChanged.Count > 0)
        {
            var f = ctx.Report.Report("JAVA",
                L($"{keyChanged.Count} key runtime properties were rewritten after startup", $"{keyChanged.Count} propiedades clave del entorno de ejecución se reescribieron tras el arranque"),
                Severity.High,
                L("The class path, the native library path, the home directory and the application command line are set at startup and normally never change. A value differing from the snapshot taken at VM start means someone rewrote the foundation the runtime uses to find code and libraries.", "La ruta de clases, la ruta de bibliotecas nativas, el directorio raíz y la línea de comandos de la aplicación se fijan al arrancar y normalmente nunca cambian. Un valor distinto de la instantánea tomada al iniciar la máquina significa que alguien reescribió la base que usa el entorno de ejecución para encontrar código y bibliotecas."));
            foreach (var (k, was, now) in keyChanged)
            {
                f.Add(k + L(" (was)", " (antes)"), JavaMeta.Clean(was, 400));
                f.Add(k + L(" (now)", " (ahora)"), JavaMeta.Clean(now, 400));
            }
        }

        removed = removed.Where(k => !StrippedByRuntime(k)).ToList();
        if (removed.Count > 0)
        {
            var f = ctx.Report.Report("JAVA",
                L($"{removed.Count} properties are in the startup snapshot but missing from the live table", $"{removed.Count} propiedades están en la instantánea del arranque pero faltan en la tabla viva"),
                Severity.Medium,
                L("A property can be removed from the live table only by calling System.clearProperty or by replacing the whole table. Neither the game nor the runtime does this. Removing one\'s own traces from the live table is a natural step for whoever put them there, and the startup snapshot shows it.", "Una propiedad solo puede eliminarse de la tabla viva llamando a System.clearProperty o sustituyendo toda la tabla. Ni el juego ni el entorno de ejecución lo hacen. Borrar sus propios rastros de la tabla viva es un paso natural para quien los puso ahí, y la instantánea del arranque lo muestra."));
            foreach (string k in removed.Take(60)) f.Add(L("removed", "eliminada"), k);
        }
    }

    private static bool StrippedByRuntime(string key) =>
        key is "jdk.boot.class.path.append" or "sun.nio.MaxDirectMemorySize" or
            "java.class.path.append" or "sun.java.launcher.diag" or
            "jdk.internal.lambda.dumpProxyClasses";

    private static bool AgentRelated(string s) =>
        s.Contains("javaagent", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("premain", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("agentmain", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("instrument", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("jdk.attach", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("attachSelf", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("bootclasspath", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("-agentlib", StringComparison.OrdinalIgnoreCase) ||
        s.Contains("-agentpath", StringComparison.OrdinalIgnoreCase);

    private static void OpenedPackages(ScanContext ctx, JavaMeta m, StringBuilder sb)
    {
        sb.AppendLine(L("PACKAGES OPENED IN ADDITION TO THE MODULE DESCRIPTOR", "PAQUETES ABIERTOS ADEMÁS DEL DESCRIPTOR DEL MÓDULO"));
        sb.AppendLine();

        var idx = ctx.HeapIndex;
        if (idx is null || !idx.Valid)
        {
            sb.AppendLine(L("  Java heap index not built — module maps were not read.", "  índice del heap de Java no construido: no se leyeron los mapas de módulos."));
            sb.AppendLine();
            return;
        }

        ulong modKlass = m.KlassByName("java/lang/Module");
        var modules = modKlass != 0 && idx.FullLive.TryGetValue(modKlass, out var allMods)
            ? allMods
            : idx.LiveInstancesOf("java/lang/Module");
        sb.AppendLine(L($"  java.lang.Module objects in the heap: {modules.Count}", $"  objetos java.lang.Module en el heap: {modules.Count}"));

        var rows = new List<(string Module, string Kind, string Package, string To)>();
        foreach (ulong mod in modules)
        {
            string name = m.StringField(mod, "name") ?? L("<unnamed module>", "<módulo sin nombre>");
            foreach (string fld in new[] { "openPackages", "exportedPackages" })
            {
                ulong map = m.OopField(mod, fld);
                if (map == 0) continue;
                string kind = fld == "openPackages" ? L("opened", "abierto") : L("exported", "exportado");
                foreach (var (pkg, targets) in ReadPackageMap(m, map))
                    rows.Add((name, kind, pkg, targets));
            }
        }

        sb.AppendLine(L($"  added open entries : {rows.Count}", $"  entradas de aperturas añadidas : {rows.Count}"));
        foreach (var r in rows.OrderBy(x => x.Module, StringComparer.Ordinal)
                     .ThenBy(x => x.Package, StringComparer.Ordinal))
            sb.AppendLine($"      {r.Module}/{r.Package} {r.Kind} → {r.To}");
        sb.AppendLine();

        if (rows.Count == 0) return;

        ReportOpens(ctx, rows);
    }

    private static IEnumerable<(string Package, string Targets)> ReadPackageMap(
        JavaMeta m, ulong map)
    {
        ulong table = m.OopField(map, "table");
        if (table == 0) yield break;

        foreach (ulong head in m.ObjArray(table, 8192))
        {
            ulong node = head;
            int guard = 0;
            while (node != 0 && guard++ < 4096)
            {
                ulong kOop = m.OopField(node, "key");
                ulong vOop = m.OopField(node, "val");
                if (vOop == 0) vOop = m.OopField(node, "value");
                string? pkg = kOop != 0 ? m.StringValue(kOop) : null;
                if (pkg is not null)
                    yield return (pkg, DescribeTargets(m, vOop));
                node = m.OopField(node, "next");
            }
        }
    }

    private static string DescribeTargets(JavaMeta m, ulong set)
    {
        if (set == 0) return L("<targets not read>", "<destinatarios no leídos>");
        var names = new List<string>();

        void AddModule(ulong mod)
        {
            if (mod == 0) return;
            string? n = m.StringField(mod, "name");
            names.Add(n is null or "" ? L("UNNAMED MODULE (whole class path)", "MÓDULO SIN NOMBRE (toda la ruta de clases)") : n);
        }

        foreach (string d in new[] { "c", "s", "m" })
        {
            ulong inner = m.OopField(set, d);
            if (inner != 0 && inner != set) { set = inner; break; }
        }

        foreach (string f in new[] { "e0", "e1" })
        {
            ulong e = m.OopField(set, f);
            if (e != 0) AddModule(e);
        }
        ulong arr = m.OopField(set, "elements");
        if (arr == 0) arr = m.OopField(set, "table");
        if (arr != 0)
            foreach (ulong e in m.ObjArray(arr, 512))
                if (e != 0) AddModule(e);

        return names.Count > 0
            ? string.Join(", ", names.Distinct().Take(8))
            : L("<targets not read>", "<destinatarios no leídos>");
    }

    private static bool FullyEncapsulated(string module) =>
        module is "java.base" or "java.management" or "java.instrument" or
            "jdk.attach" or "jdk.internal.jvmstat";

    private static void ReportOpens(ScanContext ctx,
        List<(string Module, string Kind, string Package, string To)> rows)
    {
        var opens = rows.Where(r => En(r.Kind) == "opened").ToList();
        var sensitive = opens.Where(r => FullyEncapsulated(r.Module)).ToList();
        var toUnnamed = opens.Where(r => En(r.To).Contains("UNNAMED", StringComparison.Ordinal))
            .ToList();

        if (sensitive.Count > 0)
        {
            var f = ctx.Report.Report("JAVA",
                L($"{sensitive.Count} packages of CLOSED platform modules are opened for reflection", $"{sensitive.Count} paquetes de módulos CERRADOS de la plataforma están abiertos a la reflexión"),
                Severity.High,
                L("The module system closes platform internals from reflection. A package can be opened with --add-opens at startup or with a Modules.addOpens call at runtime; both are recorded in the openPackages map of the module object, while the normal opens from the module descriptor do NOT go into this map. So every entry is somebody\'s decision. There is no way to close the package again: the entry survives even when whoever made it is gone. Opened platform packages are a mandatory step for foreign code: without them it cannot get a trusted Lookup, Unsafe or access to private platform fields. Compare the list with the --add-opens flags on the command line: whatever is not there was opened from inside the process.", "El sistema de módulos cierra las partes internas de la plataforma a la reflexión. Un paquete puede abrirse con --add-opens al arrancar o con una llamada a Modules.addOpens durante la ejecución; ambas se registran en el mapa openPackages del objeto del módulo, mientras que las aperturas normales del descriptor del módulo NO entran en ese mapa. Por tanto, cada entrada es una decisión de alguien. No hay forma de volver a cerrar el paquete: la entrada sobrevive aunque quien la creó ya no esté. Abrir paquetes de la plataforma es un paso obligatorio para el código ajeno: sin ello no puede obtener un Lookup de confianza, Unsafe ni acceso a campos privados de la plataforma. Compare la lista con las opciones --add-opens de la línea de comandos: lo que no esté ahí se abrió desde dentro del proceso."));
            foreach (var r in sensitive.Take(60))
                f.Add($"{r.Module}/{r.Package}", L("opened → ", "abierto → ") + r.To);
        }

        if (toUnnamed.Count > 0 && sensitive.Count == 0)
        {
            var f = ctx.Report.Report("JAVA",
                L($"{toUnnamed.Count} packages are opened to the unnamed module (the whole class path)", $"{toUnnamed.Count} paquetes están abiertos al módulo sin nombre (toda la ruta de clases)"),
                Severity.Info,
                L("Opening to the unnamed module lifts the restriction for ALL code loaded from the class path, not for one named module. The entry was made either with --add-opens or by a call from inside the process, and is never cleared.", "Abrir al módulo sin nombre elimina la restricción para TODO el código cargado desde la ruta de clases, no para un único módulo con nombre. La entrada se creó con --add-opens o con una llamada desde dentro del proceso, y nunca se borra."));
            foreach (var r in toUnnamed.Take(60))
                f.Add($"{r.Module}/{r.Package}", L("opened → ", "abierto → ") + r.To);
        }
    }

    private static void NativeLibraries(ScanContext ctx, JavaMeta m, StringBuilder sb)
    {
        sb.AppendLine(L("NATIVE LIBRARIES AS SEEN BY JAVA ITSELF", "BIBLIOTECAS NATIVAS VISTAS POR LA PROPIA JAVA"));
        sb.AppendLine();

        var idx = ctx.HeapIndex;
        if (idx is null || !idx.Valid)
        {
            sb.AppendLine(L("  Java heap index not built — the library registry was not read.", "  índice del heap de Java no construido: no se leyó el registro de bibliotecas."));
            sb.AppendLine();
            return;
        }

        var names = m.KlassesWhere(n =>
            n.EndsWith("NativeLibraries$NativeLibraryImpl", StringComparison.Ordinal) ||
            n.EndsWith("ClassLoader$NativeLibrary", StringComparison.Ordinal) ||
            n.EndsWith("NativeLibraries$NativeLibraryContext", StringComparison.Ordinal))
            .Select(x => x.Name).Distinct().ToList();

        if (names.Count == 0)
        {
            sb.AppendLine(L("  native library registry class not found in this VM.", "  no se encontró la clase del registro de bibliotecas nativas en esta VM."));
            sb.AppendLine();
            return;
        }

        var rows = new List<(string Lib, ulong Handle, string From, string Module, bool Builtin)>();
        foreach (string cls in names)
        {
            sb.AppendLine(L($"  registry class: {cls}", $"  clase del registro: {cls}"));
            foreach (ulong obj in idx.LiveInstancesOf(cls))
            {
                string lib = m.StringField(obj, "name") ?? "";
                long handle = m.LongField(obj, "handle");
                ulong fromClass = m.OopField(obj, "fromClass");
                bool builtin = false;
                int bo = m.FieldOffset(m.KlassOf(obj), "isBuiltin");
                if (bo >= 0) builtin = ctx.Target.ReadU8(obj + (ulong)bo) != 0;

                string from = fromClass != 0 ? MirrorClassName(ctx, m, fromClass) : "";
                string module = DescribeHandle(ctx, (ulong)handle);
                rows.Add((lib, (ulong)handle, from, module, builtin));
            }
        }

        sb.AppendLine(L($"  entries found: {rows.Count}", $"  entradas encontradas: {rows.Count}"));
        foreach (var r in rows.OrderBy(x => x.Lib, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine(L($"      {(r.Lib.Length > 0 ? r.Lib : "<name not read>")}", $"      {(r.Lib.Length > 0 ? r.Lib : "<nombre no leído>")}"));
            sb.AppendLine(L($"          handle 0x{r.Handle:X} → {r.Module}{(r.Builtin ? ", built into the runtime" : "")}", $"          handle 0x{r.Handle:X} → {r.Module}{(r.Builtin ? ", integrada en el entorno de ejecución" : "")}"));
            if (r.From.Length > 0) sb.AppendLine(L($"          load requested by class: {r.From}", $"          carga solicitada por la clase: {r.From}"));
        }
        sb.AppendLine();

        ReportDetachedLibraries(ctx, rows);
        ReportForeignLoaders(ctx, rows);
    }

    private static string DescribeHandle(ScanContext ctx, ulong handle)
    {
        if (handle == 0) return L("handle is zero", "handle nulo");
        var im = ctx.ImageAt(handle);
        if (im is not null)
            return handle == im.Base
                ? im.Name
                : L($"{im.Name}+0x{handle - im.Base:X} (not a module base)", $"{im.Name}+0x{handle - im.Base:X} (no es la base de un módulo)");
        var r = ctx.RegionAt(handle);
        return r is null
            ? L("NO MODULE AT THIS ADDRESS (memory not mapped)", "NO HAY MÓDULO EN ESTA DIRECCIÓN (memoria no proyectada)")
            : L($"NO MODULE AT THIS ADDRESS ({r.TypeString}/{r.ProtectString})", $"NO HAY MÓDULO EN ESTA DIRECCIÓN ({r.TypeString}/{r.ProtectString})");
    }

    private static string MirrorClassName(ScanContext ctx, JavaMeta m, ulong mirror)
    {
        ulong a = m.Vm.StaticAddr("java_lang_Class", "_klass_offset");
        if (a != 0)
        {
            int off = (int)m.Cache.U32(a);
            if (off is > 0 and < 4096)
            {
                ulong klass = m.Cache.U64(mirror + (ulong)off);
                string? n = klass is >= 0x10000 and <= 0x7FFFFFFFFFFFFF
                    ? m.KlassName(klass)
                    : null;
                if (n is not null) return n;
            }
        }
        return m.Describe(mirror);
    }

    private static void ReportDetachedLibraries(ScanContext ctx,
        List<(string Lib, ulong Handle, string From, string Module, bool Builtin)> rows)
    {
        var hits = rows.Where(r => !r.Builtin && r.Handle != 0 &&
                                   En(r.Module).StartsWith("NO MODULE", StringComparison.Ordinal))
            .ToList();
        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            L($"{hits.Count} native libraries are listed by Java as loaded, but there is no module at their handle in the process", $"{hits.Count} bibliotecas nativas figuran en Java como cargadas, pero en el proceso no hay ningún módulo en su handle"),
            Severity.High,
            L("The handle of a loaded library is the base of its module in the address space. While the library is loaded, a PE image lies at this address and the module is visible in the loader lists. A Java heap entry with a handle where there is no module any more means the library was unloaded while the object describing it survived in the heap. This is exactly what the native part of a cheat looks like after being switched off: the code is gone, but its Java heap entry remains and names both the file and the class that loaded it.", "El handle de una biblioteca cargada es la base de su módulo en el espacio de direcciones. Mientras la biblioteca está cargada, en esa dirección hay una imagen PE y el módulo es visible en las listas del cargador. Una entrada del heap de Java con un handle en el que ya no hay módulo significa que la biblioteca se descargó mientras el objeto que la describe sobrevivió en el heap. Así es exactamente la parte nativa de un cheat después de desactivarlo: el código desapareció, pero su entrada en el heap de Java sigue ahí y nombra tanto el archivo como la clase que lo cargó."));
        foreach (var r in hits)
            f.Add(r.Lib.Length > 0 ? r.Lib : $"0x{r.Handle:X}",
                L($"handle 0x{r.Handle:X}, {r.Module}", $"handle 0x{r.Handle:X}, {r.Module}") +
                (r.From.Length > 0 ? L($", loaded by class {r.From}", $", cargada por la clase {r.From}") : ""));
    }

    private static void ReportForeignLoaders(ScanContext ctx,
        List<(string Lib, ulong Handle, string From, string Module, bool Builtin)> rows)
    {
        if (ctx.Jars is null) return;
        var hits = rows.Where(r => NoOriginOnDisk(ctx, r.From)).ToList();
        if (hits.Count == 0) return;

        var f = ctx.Report.Report("JVM",
            L($"{hits.Count} native libraries were loaded by classes that are not in any archive available to the game", $"{hits.Count} bibliotecas nativas fueron cargadas por clases que no están en ningún archivo disponible para el juego"),
            Severity.Critical,
            L("For every successful System.loadLibrary or System.load the runtime remembers the class that requested the load. A class with no file on disk that loaded a native library is foreign code that had a native part. The entry survives both unloading the library and wiping the bytecode of the class that loaded it.", "Por cada System.loadLibrary o System.load correcto, el entorno de ejecución recuerda la clase que solicitó la carga. Una clase sin archivo en disco que cargó una biblioteca nativa es código ajeno que tenía una parte nativa. La entrada sobrevive tanto a la descarga de la biblioteca como al borrado del bytecode de la clase que la cargó."));
        foreach (var r in hits)
            f.Add(r.From, L($"library {r.Lib}, handle 0x{r.Handle:X}, {r.Module}", $"biblioteca {r.Lib}, handle 0x{r.Handle:X}, {r.Module}"));
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

    private static ulong StaticOop(JavaMeta m, int offMirror, string className, string field)
    {
        ulong klass = m.KlassByName(className);
        if (klass == 0) return 0;
        ulong handle = m.Cache.U64(klass + (ulong)offMirror);
        if (handle is < 0x1000 or > 0x7FFFFFFFFFFF) return 0;
        ulong mirror = m.Cache.U64(handle);
        if (mirror is < 0x1000 or > 0x7FFFFFFFFFFF) return 0;
        foreach (var f in m.DeclaredFields(klass))
        {
            if (!f.IsStatic || f.Name != field) continue;
            if (!f.Signature.StartsWith('L') && !f.Signature.StartsWith('[')) return 0;
            return m.Oop(mirror, f.Offset);
        }
        return 0;
    }

    private static Dictionary<string, string> ReadMap(JavaMeta m, ulong obj, int depth = 0)
    {
        var res = new Dictionary<string, string>(StringComparer.Ordinal);
        if (obj == 0 || depth > 3) return res;

        ulong klass = m.KlassOf(obj);
        string name = m.KlassName(klass) ?? "";

        if (name.EndsWith("/Properties", StringComparison.Ordinal))
        {
            ulong inner = m.OopField(obj, "map");
            if (inner != 0) return ReadMap(m, inner, depth + 1);
        }
        foreach (string delegateField in new[] { "m", "map", "delegate" })
        {
            if (name.Contains("Unmodifiable", StringComparison.Ordinal) ||
                name.Contains("Synchronized", StringComparison.Ordinal))
            {
                ulong inner = m.OopField(obj, delegateField);
                if (inner != 0 && inner != obj) return ReadMap(m, inner, depth + 1);
            }
        }

        ulong table = m.OopField(obj, "table");
        if (table == 0) return res;

        var cells = m.ObjArray(table);

        if (name.Contains("ImmutableCollections", StringComparison.Ordinal))
        {
            for (int i = 0; i + 1 < cells.Count; i += 2)
            {
                string? k = cells[i] == 0 ? null : m.StringValue(cells[i]);
                if (k is null) continue;
                res[k] = (cells[i + 1] == 0 ? null : m.StringValue(cells[i + 1])) ?? "";
            }
            return res;
        }

        foreach (ulong head in cells)
        {
            ulong node = head;
            int guard = 0;
            while (node != 0 && guard++ < 4096)
            {
                ulong kOop = m.OopField(node, "key");
                ulong vOop = m.OopField(node, "val");
                if (vOop == 0) vOop = m.OopField(node, "value");
                string? k = kOop != 0 ? m.StringValue(kOop) : null;
                if (k is not null)
                    res[k] = (vOop != 0 ? m.StringValue(vOop) : null) ?? "";
                node = m.OopField(node, "next");
            }
        }
        return res;
    }
}
