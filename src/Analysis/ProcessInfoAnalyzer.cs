using System.Text;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal static class ProcessInfoAnalyzer
{
    public static void Run(ScanContext ctx)
    {
        var t = ctx.Target;
        var rep = ctx.Report;

        var f = rep.Report(L("PROCESS", "PROCESO"), L($"Target: PID {t.Pid}", $"Objetivo: PID {t.Pid}"), Severity.Info, null);
        f.Add(L("image", "imagen"), t.ImagePath);
        f.Add(L("started", "iniciado"), t.StartTimeUtc == default ? "-" : t.StartTimeUtc.ToLocalTime().ToString("O"));
        if (t.StartTimeUtc != default)
            f.Add(L("running for", "en ejecución"), L($"{(DateTime.UtcNow - t.StartTimeUtc).TotalMinutes:F1} min", $"{(DateTime.UtcNow - t.StartTimeUtc).TotalMinutes:F1} min"));
        f.Add("PEB", t.PebAddress == IntPtr.Zero ? L("unavailable", "no disponible") : $"0x{t.PebAddress.ToInt64():X}");
        f.Add("ImageBase", t.ImageBase);
        f.Add("WOW64", t.IsWow64 ? L("yes (32-bit process)", "sí (proceso de 32 bits)") : L("no (native x64)", "no (x64 nativo)"));
        f.Add(L("handle opened with access", "handle abierto con permisos"), t.OpenedWith);
        foreach (var w in t.Warnings) f.Add(L("warning", "advertencia"), w);

        rep.AddMeta("PID", t.Pid.ToString());
        rep.AddMeta(L("Image", "Imagen"), t.ImagePath.Length > 0 ? t.ImagePath : "-");
        rep.AddMeta(L("Started", "Iniciado"), t.StartTimeUtc == default
            ? "-"
            : t.StartTimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
        if (t.StartTimeUtc != default)
            rep.AddMeta(L("Running at scan time", "En ejecución al comprobar"),
                L($"{(DateTime.UtcNow - t.StartTimeUtc).TotalMinutes:F1} min", $"{(DateTime.UtcNow - t.StartTimeUtc).TotalMinutes:F1} min"));
        rep.AddMeta(L("Working directory", "Directorio de trabajo"), t.GetCurrentDirectory() ?? "-");
        rep.AddMeta(L("Command line", "Línea de comandos"), t.GetCommandLine() ?? "-");
        rep.AddMeta(L("Bitness", "Arquitectura"), t.IsWow64 ? L("WOW64 (32-bit)", "WOW64 (32 bits)") : "x64");
        rep.AddMeta(L("Parent process", "Proceso padre"), t.ParentPid.ToString());
        rep.AddMeta(L("Handle opened with access", "Handle abierto con permisos"), t.OpenedWith);
        rep.AddMeta("PEB", t.PebAddress == IntPtr.Zero
            ? L("unavailable", "no disponible") : $"0x{t.PebAddress.ToInt64():X}");

        rep.Section(L("PROCESS", "PROCESO"), Render(ctx));
    }

    private static string Render(ScanContext ctx)
    {
        var t = ctx.Target;
        var sb = new StringBuilder();
        sb.AppendLine($"PID           : {t.Pid}");
        sb.AppendLine(L($"Image         : {t.ImagePath}", $"Imagen        : {t.ImagePath}"));
        sb.AppendLine(L($"Started       : {(t.StartTimeUtc == default ? "-" : t.StartTimeUtc.ToLocalTime().ToString("O"))}", $"Iniciado      : {(t.StartTimeUtc == default ? "-" : t.StartTimeUtc.ToLocalTime().ToString("O"))}"));
        sb.AppendLine($"PEB           : 0x{t.PebAddress.ToInt64():X}");
        sb.AppendLine($"ImageBase     : 0x{t.ImageBase:X}");
        sb.AppendLine(L($"Work dir      : {t.GetCurrentDirectory() ?? "-"}", $"Dir. trabajo  : {t.GetCurrentDirectory() ?? "-"}"));
        sb.AppendLine();
        sb.AppendLine(L("Command line:", "Línea de comandos:"));
        sb.AppendLine("  " + (t.GetCommandLine() ?? "-"));
        sb.AppendLine();
        sb.AppendLine(L("Process environment:", "Entorno del proceso:"));
        foreach (var e in t.GetEnvironment().OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            sb.AppendLine("  " + e);
        return sb.ToString();
    }
}
