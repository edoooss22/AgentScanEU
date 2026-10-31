using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using AgentScan.Analysis;
using AgentScan.Core;
using AgentScan.Report;

namespace AgentScan;

internal static class Program
{
    public const string Version = "1.2";
    public const string Tool = "AgentScan";

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            EnableDebugPrivilege();
            Gui.MainForm.RunApp();
            return 0;
        }

        AttachConsole(AttachParentProcess);
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }

        var opt = Options.Parse(args);
        if (opt.ShowHelp) { Options.PrintHelp(); return 0; }

        if (!EnableDebugPrivilege())
            Console.Error.WriteLine(
                "WARNING: failed to enable SeDebugPrivilege. Run the scanner as administrator — otherwise a process of another user is unavailable and part of the thread data cannot be read.");

        if (opt.ListOnly)
        {
            PrintCandidates();
            return 0;
        }

        int pid = opt.Pid;
        if (pid <= 0)
        {
            var cands = ProcessTarget.FindJavaProcesses();
            var mc = cands.Where(c => c.LooksLikeMinecraft).ToList();
            if (mc.Count == 0)
            {
                Console.Error.WriteLine("Minecraft process (java/javaw) not found. Specify the PID manually: --pid <N>");
                PrintCandidates();
                return 2;
            }
            if (mc.Count > 1)
            {
                Console.Error.WriteLine("Several matching processes found, specify --pid:");
                foreach (var c in mc)
                    Console.Error.WriteLine($"  PID {c.Pid}  {c.Name}  ({c.Reason})");
                return 2;
            }
            pid = mc[0].Pid;
        }

        ScanOutcome res;
        try
        {
            res = ScanRunner.Run(pid, opt);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Fatal error: {ex}");
            return 3;
        }

        var console = new ConsoleWriter(opt.Verbose);
        console.Write(Localize(res.Report, "en"), res.Elapsed);

        Console.WriteLine();
        foreach (var line in res.Log) Console.WriteLine(line);
        foreach (var line in res.Errors) Console.Error.WriteLine(line);

        return ScanRunner.ExitCode(res.Report);
    }

    private const int AttachParentProcess = -1;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int dwProcessId);

    internal static bool EnableDebugPrivilege()
    {
        bool ok = Native.NativeApi.EnablePrivilege("SeDebugPrivilege");
        Core.SelfProcess.HasDebugPrivilege = ok;
        return ok;
    }

    private static void PrintCandidates()
    {
        Console.WriteLine("Java processes in the system:");
        foreach (var c in ProcessTarget.FindJavaProcesses())
        {
            Console.WriteLine($"  PID {c.Pid,-8} {c.Name,-8} MC={(c.LooksLikeMinecraft ? "yes" : "no"),-4} start={c.StartUtc.ToLocalTime():HH:mm:ss}  {c.ExePath}");
            if (c.CommandLine.Length > 0)
                Console.WriteLine($"      cmd: {Truncate(c.CommandLine, 300)}");
        }
    }

    internal static string Truncate(string s, int n) =>
        s.Length <= n ? s : s.Substring(0, n) + $"... (+{s.Length - n} chars)";
}

internal sealed class ScanOutcome
{
    public required ScanReport Report { get; init; }
    public TimeSpan Elapsed { get; init; }
    public string? HtmlPath { get; set; }
    public string? TxtPath { get; set; }
    public string? JsonPath { get; set; }
    public List<string> Log { get; } = new();
    public List<string> Errors { get; } = new();
}

internal static class ScanRunner
{
    public static ScanOutcome Run(int pid, Options opt)
    {
        var sw = Stopwatch.StartNew();
        var report = Scanner.Run(pid, opt);
        sw.Stop();

        var res = new ScanOutcome { Report = report, Elapsed = sw.Elapsed };

        string outDir = opt.OutputDir ?? Path.Combine(AppContext.BaseDirectory, "reports");
        try { Directory.CreateDirectory(outDir); }
        catch (Exception ex)
        {
            res.Errors.Add($"Failed to create the report directory {outDir}: {ex.Message}");
        }

        string st = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        res.HtmlPath = Write(res, "HTML report ", Path.Combine(outDir, $"agentscan-{pid}-{st}.html"),
            () => HtmlReport.Render(report, pid, res.Elapsed), false, "   ← open in a browser");
        res.TxtPath = Write(res, "Full text  ", Path.Combine(outDir, $"agentscan-{pid}-{st}.txt"),
            () => TextReport.Render(Localize(report, "en"), pid, res.Elapsed), true);
        res.JsonPath = Write(res, "JSON        ", Path.Combine(outDir, $"agentscan-{pid}-{st}.json"),
            () => JsonReport.Render(Localize(report, "en"), pid, res.Elapsed), false);

        if (opt.DumpDir is not null && Directory.Exists(opt.DumpDir))
        {
            var files = Directory.GetFiles(opt.DumpDir);
            long total = files.Sum(f => new FileInfo(f).Length);
            res.Log.Add($"Dumps       : {opt.DumpDir}   ({files.Length} files, {total / 1024.0 / 1024.0:F1} MB)");
        }
        return res;
    }

    public static int ExitCode(ScanReport report)
    {
        if (report.Count(Severity.Critical) > 0) return 10;
        if (report.Count(Severity.High) > 0) return 9;
        if (report.Count(Severity.Medium) > 0) return 8;
        return 0;
    }

    private static string? Write(ScanOutcome res, string label, string path, Func<string> render,
        bool bom, string suffix = "")
    {
        try
        {
            File.WriteAllText(path, render(), new UTF8Encoding(bom));
            res.Log.Add($"{label}: {path}{suffix}");
            return path;
        }
        catch (Exception ex)
        {
            res.Errors.Add($"{label}: NOT WRITTEN — {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }
}

internal sealed class Options
{
    public int Pid;
    public bool ListOnly;
    public bool ShowHelp;
    public bool Verbose;
    public string? OutputDir;
    public string? DumpDir;

    public bool FullStringScan = true;

    public bool DumpSuspicious = true;

    public List<string> OnlySteps = new();
    public List<string> SkipSteps = new();

    public long MaxDumpBytes = 256L * 1024 * 1024;

    public long ScanBudgetBytes = long.MaxValue;

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a.ToLowerInvariant())
            {
                case "-h" or "--help" or "/?": o.ShowHelp = true; break;
                case "-l" or "--list": o.ListOnly = true; break;
                case "-c" or "--console": break;
                case "-v" or "--verbose": o.Verbose = true; break;
                case "-p" or "--pid":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out int p)) o.Pid = p;
                    break;
                case "-o" or "--out":
                    if (i + 1 < args.Length) o.OutputDir = args[++i];
                    break;
                case "--dump-dir":
                    if (i + 1 < args.Length) o.DumpDir = args[++i];
                    break;
                case "--max-dump":
                    if (i + 1 < args.Length && long.TryParse(args[++i], out long mb) && mb > 0)
                        o.MaxDumpBytes = mb * 1024 * 1024;
                    break;
                case "--no-strings": o.FullStringScan = false; break;
                case "--no-dump": o.DumpSuspicious = false; break;
                case "--only":
                    if (i + 1 < args.Length)
                        o.OnlySteps.AddRange(args[++i]
                            .Split(',', StringSplitOptions.RemoveEmptyEntries |
                                        StringSplitOptions.TrimEntries));
                    break;
                case "--skip":
                    if (i + 1 < args.Length)
                        o.SkipSteps.AddRange(args[++i]
                            .Split(',', StringSplitOptions.RemoveEmptyEntries |
                                        StringSplitOptions.TrimEntries));
                    break;
                case "--fast":
                    o.FullStringScan = false;
                    o.DumpSuspicious = false;
                    break;
                default:
                    if (int.TryParse(a, out int bare) && o.Pid == 0) o.Pid = bare;
                    break;
            }
        }
        if (o.DumpSuspicious && o.DumpDir is null)
            o.DumpDir = Path.Combine(o.OutputDir ?? Path.Combine(AppContext.BaseDirectory, "reports"),
                $"agentscan-dumps-{DateTime.Now:yyyyMMdd-HHmmss}");
        return o;
    }

    public static void PrintHelp()
    {
        Console.WriteLine($"""
        AgentScan {Program.Version} — Minecraft process mini scanner: JVMTI, Java agents
        and the virtual machine environment, including agents that are already detached.

        After the scan three files are written: .html (for reading — with filters,
        search and explanations; English/Spanish switch), .txt (full text) and .json
        (for automation).

        Usage:
          AgentScan.exe                       window: process selection, progress, report
          AgentScan.exe --pid <N> [options]   console mode
          AgentScan.exe --console [options]   console mode, the process is found automatically

          --pid, -p <N>     game process PID (found automatically by default)
          --list, -l        list Java processes and exit
          --out, -o <dir>   report directory (default ./reports)
          --dump-dir <dir>  directory for dumps of found residues
          --verbose, -v     verbose console output
          --max-dump <MB>   limit for one dump (default 256 MB)
          --no-strings      skip the full memory scan (fast, but some checks
                            will have no data)
          --no-dump         do not save dumps
          --fast            = --no-strings --no-dump
          --only <part,...>    run only steps whose name contains a substring
                               (scanner self-test mode; the report is marked incomplete)
          --skip <part,...>    the opposite: skip such steps

        Exit codes: 10 — CRITICAL found, 9 — HIGH, 8 — MEDIUM, 0 — clean,
        2 — process not found, 3 — fatal error.

        Run as administrator.
        """);
    }
}
