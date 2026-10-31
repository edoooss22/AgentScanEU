using System.Text;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class JvmExtraAnalyzer
{
    public static void Run(ScanContext ctx, SweepResult sweep)
    {
        CheckJavaVmTable(ctx);
        if (sweep.Classes.Count > 0) CheckRedefinedClasses(ctx, sweep);
    }

    private static void CheckJavaVmTable(ScanContext ctx)
    {
        var jvm = JvmAnalyzer.FindJvm(ctx);
        if (jvm is null || !jvm.Pe.Valid) return;

        var text = jvm.Pe.Sections.Where(s => s.IsExecutable).ToList();
        ulong lo = jvm.Base, hi = jvm.Base + jvm.Size;
        bool InText(ulong p)
        {
            if (p < lo || p >= hi) return false;
            uint rva = (uint)(p - lo);
            return text.Any(s => rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize);
        }

        var sb = new StringBuilder();
        int found = 0;

        foreach (var sec in jvm.Pe.Sections)
        {
            if (sec.IsExecutable || sec.Name is not (".rdata" or ".data")) continue;
            if (sec.VirtualSize is 0 or > 64 * 1024 * 1024) continue;
            var buf = new byte[sec.VirtualSize];
            ctx.Target.ReadPartial(jvm.Base + sec.VirtualAddress, buf, out _);
            ulong secVa = jvm.Base + sec.VirtualAddress;

            for (int i = 0; i + 8 * 8 <= buf.Length; i += 8)
            {
                if (BitConverter.ToUInt64(buf, i) != 0) continue;
                if (BitConverter.ToUInt64(buf, i + 8) != 0) continue;
                if (BitConverter.ToUInt64(buf, i + 16) != 0) continue;

                var slots = new ulong[5];
                int inText = 0, foreign = 0;
                bool bad = false;
                for (int k = 0; k < 5; k++)
                {
                    slots[k] = BitConverter.ToUInt64(buf, i + 24 + k * 8);
                    if (InText(slots[k])) { inText++; continue; }
                    var r = ctx.RegionAt(slots[k]);
                    if (r is null || !r.IsCommitted || !r.IsExecutable) { bad = true; break; }
                    foreign++;
                }
                if (bad || inText < 4 || inText + foreign != 5) continue;
                if (i + 64 + 8 <= buf.Length && InText(BitConverter.ToUInt64(buf, i + 64))) continue;

                ulong addr = secVa + (ulong)i;
                found++;
                sb.AppendLine(L($"  0x{addr:X}  into jvm.dll: {inText}/5, outside: {foreign}", $"  0x{addr:X}  dentro de jvm.dll: {inText}/5, fuera: {foreign}"));
                string[] names =
                {
                    "DestroyJavaVM", "AttachCurrentThread", "DetachCurrentThread",
                    "GetEnv", "AttachCurrentThreadAsDaemon",
                };
                for (int k = 0; k < 5; k++)
                    sb.AppendLine($"      {names[k],-28} {ctx.Describe(slots[k])}");

                if (foreign == 0) continue;

                var f = ctx.Report.Report("JVM",
                    L($"JNIInvokeInterface_ (JavaVM) table at 0x{addr:X}: {foreign} slots lead outside jvm.dll", $"Tabla JNIInvokeInterface_ (JavaVM) en 0x{addr:X}: {foreign} entradas apuntan fuera de jvm.dll"),
                    Severity.Critical,
                    L("Native code gets access to the JVM through the JavaVM table (AttachCurrentThread → JNIEnv). All its slots must point into jvm.dll code. A slot leading outside is a hook on the JVM entry point: exactly what a native cheat does to work with game objects.", "El código nativo accede a la JVM a través de la tabla JavaVM (AttachCurrentThread → JNIEnv). Todas sus entradas deben apuntar al código de jvm.dll. Una entrada que apunta fuera es un hook en el punto de entrada de la JVM: justo lo que hace un cheat nativo para trabajar con los objetos del juego."));
                f.Add(L("table address", "dirección de la tabla"), addr);
                for (int k = 0; k < 5; k++)
                    f.Add(names[k], $"0x{slots[k]:X} → {ctx.Describe(slots[k])}");
                if (found > 8) return;
            }
        }

        ctx.Report.Section(L("JavaVM TABLE (JNIInvokeInterface_)", "TABLA JavaVM (JNIInvokeInterface_)"),
            found == 0 ? L("No candidates found.", "No se encontraron candidatos.") : sb.ToString());
    }

    private static void CheckRedefinedClasses(ScanContext ctx, SweepResult sweep)
    {
        var dup = sweep.Classes.Values.Where(c => c.Occurrences > 1)
            .OrderByDescending(c => c.Occurrences).ToList();
        if (dup.Count == 0) return;

        var mc = dup.Where(c => c.Name.StartsWith("net/minecraft/", StringComparison.Ordinal) ||
                                c.Name.StartsWith("com/mojang/", StringComparison.Ordinal))
                    .ToList();

        var sb = new StringBuilder();
        foreach (var c in dup.Take(300))
            sb.AppendLine($"  ×{c.Occurrences,-3} {c.Name}   " +
                          string.Join(", ", c.AllAddresses.Take(6).Select(a => $"0x{a:X}")));

        ctx.Report.Report("JAVA",
                L($"{dup.Count} classes are present in memory in several copies (game classes among them: {mc.Count})", $"{dup.Count} clases están en memoria en varias copias (de ellas, clases del juego: {mc.Count})"),
                Severity.Info,
                L("Bytecode of the same class lying in memory several times is a typical trace of transformation: the agent receives the original bytes through a ClassFileTransformer, returns modified ones, and both versions stay in the heap. RedefineClasses/RetransformClasses give the same. Duplicates also happen normally (class loader caches, Fabric Mixin when building classes), so look at the NAMES: duplicated net/minecraft/* classes are what a Java cheat patching the game on the fly does.", "El bytecode de una misma clase presente varias veces en memoria es un rastro típico de transformación: el agente recibe los bytes originales mediante un ClassFileTransformer, devuelve los modificados y ambas versiones quedan en el heap. RedefineClasses/RetransformClasses producen lo mismo. Los duplicados también aparecen de forma normal (cachés del cargador de clases, Mixin de Fabric al construir clases), así que fíjese en los NOMBRES: duplicar clases net/minecraft/* es lo que hace un cheat de Java que parchea el juego en caliente."))
            .Add(L("total duplicates", "duplicados en total"), dup.Count.ToString())
            .Add(L("game classes among them", "de ellos, clases del juego"), mc.Count.ToString())
            .Block(L("Classes", "Clases"), sb.ToString().TrimEnd());
    }
}
