using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AgentScan.Report;

internal sealed class ConsoleWriter
{
    private readonly bool _verbose;
    public ConsoleWriter(bool verbose) => _verbose = verbose;

    public void Write(ScanReport rep, TimeSpan elapsed)
    {
        Console.WriteLine();
        Line('=');
        Console.WriteLine("  SCAN RESULT");
        Line('=');

        var order = new[] { Severity.Critical, Severity.High, Severity.Medium,
                            Severity.Low, Severity.Info };

        foreach (var sev in order)
        {
            var items = rep.Findings.Where(f => f.Severity == sev).ToList();
            if (items.Count == 0) continue;
            if (sev == Severity.Info && !_verbose) continue;

            Console.WriteLine();
            WithColor(ColorFor(sev), () =>
                Console.WriteLine($"── {Label(sev)} ({items.Count}) " + new string('─', 40)));

            foreach (var f in items)
            {
                WithColor(ColorFor(sev), () => Console.Write("  ● "));
                Console.WriteLine($"[{f.Category}] {f.Title}");
                if (_verbose)
                {
                    if (f.Explanation is not null)
                        foreach (var l in Wrap(f.Explanation, 100))
                            Console.WriteLine("      " + l);
                    foreach (var (k, v) in f.Data.Take(12))
                        Console.WriteLine($"      {k}: {Short(v)}");
                }
            }
        }

        Console.WriteLine();
        Line('=');
        Console.WriteLine($"  Critical: {rep.Count(Severity.Critical)}   High: {rep.Count(Severity.High)}   Medium: {rep.Count(Severity.Medium)}   Low: {rep.Count(Severity.Low)}   Info: {rep.Count(Severity.Info)}");
        Console.WriteLine($"  Time: {elapsed.TotalSeconds:F1} s");
        Line('=');

        Console.WriteLine();
        WriteVerdict(rep);

        if (rep.Errors.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"Errors during the scan ({rep.Errors.Count}) — some checks may not have run:");
            foreach (var e in rep.Errors.Take(_verbose ? 100 : 10))
                Console.WriteLine("  " + e.Split('\n')[0]);
        }
    }

    private static void WriteVerdict(ScanReport rep)
    {
        int crit = rep.Count(Severity.Critical), high = rep.Count(Severity.High);
        if (crit > 0)
        {
            WithColor(ConsoleColor.Red, () =>
                Console.WriteLine("  VERDICT: signs of foreign code found in the process."));
            Console.WriteLine("  Review the critical findings manually — the scanner does not decide for a human.");
        }
        else if (high > 0)
        {
            WithColor(ConsoleColor.Yellow, () =>
                Console.WriteLine("  VERDICT: there are anomalies that need manual review."));
        }
        else
        {
            WithColor(ConsoleColor.Green, () =>
                Console.WriteLine("  VERDICT: no clear traces of agents or JVMTI found."));
            Console.WriteLine("  This is not a guarantee of cleanliness: some traces disappear when memory is overwritten.");
        }
    }

    private static string Label(Severity s) => s switch
    {
        Severity.Critical => "CRITICAL",
        Severity.High => "HIGH",
        Severity.Medium => "MEDIUM",
        Severity.Low => "LOW",
        _ => "INFO",
    };

    private static ConsoleColor ColorFor(Severity s) => s switch
    {
        Severity.Critical => ConsoleColor.Red,
        Severity.High => ConsoleColor.Yellow,
        Severity.Medium => ConsoleColor.Cyan,
        Severity.Low => ConsoleColor.DarkGray,
        _ => ConsoleColor.Gray,
    };

    private static void WithColor(ConsoleColor c, Action a)
    {
        var old = Console.ForegroundColor;
        try { Console.ForegroundColor = c; a(); }
        finally { Console.ForegroundColor = old; }
    }

    private static void Line(char c) => Console.WriteLine(new string(c, 78));

    private static string Short(string s)
    {
        s = s.Replace("\r", "").Replace("\n", " ");
        return s.Length <= 140 ? s : s.Substring(0, 140) + "…";
    }

    internal static IEnumerable<string> Wrap(string text, int width)
    {
        var words = text.Split(' ');
        var sb = new StringBuilder();
        foreach (var w in words)
        {
            if (sb.Length + w.Length + 1 > width) { yield return sb.ToString(); sb.Clear(); }
            if (sb.Length > 0) sb.Append(' ');
            sb.Append(w);
        }
        if (sb.Length > 0) yield return sb.ToString();
    }
}

internal static class TextReport
{
    public static string Render(ScanReport rep, int pid, TimeSpan elapsed)
    {
        var sb = new StringBuilder();
        sb.AppendLine(new string('=', 100));
        sb.AppendLine($"AgentScan {Program.Version} — process scan report: JVMTI, Java agents, VM environment");
        sb.AppendLine($"Date        : {DateTime.Now:O}");
        sb.AppendLine($"PID         : {pid}");
        sb.AppendLine($"Host        : {Environment.MachineName} / {Environment.UserName}");
        sb.AppendLine($"OS          : {Environment.OSVersion.VersionString}");
        sb.AppendLine($"Duration    : {elapsed.TotalSeconds:F1} s");
        sb.AppendLine(new string('=', 100));
        sb.AppendLine();
        sb.AppendLine($"TOTAL: critical {rep.Count(Severity.Critical)}, high {rep.Count(Severity.High)}, medium {rep.Count(Severity.Medium)}, low {rep.Count(Severity.Low)}, info {rep.Count(Severity.Info)}");
        sb.AppendLine();

        var order = new[] { Severity.Critical, Severity.High, Severity.Medium,
                            Severity.Low, Severity.Info };
        int n = 0;
        foreach (var sev in order)
        {
            var items = rep.Findings.Where(f => f.Severity == sev).ToList();
            if (items.Count == 0) continue;
            sb.AppendLine();
            sb.AppendLine(new string('#', 100));
            sb.AppendLine($"#  {sev.ToString().ToUpperInvariant()} ({items.Count})");
            sb.AppendLine(new string('#', 100));

            foreach (var f in items)
            {
                n++;
                sb.AppendLine();
                sb.AppendLine($"[{n}] [{f.Category}] {f.Title}");
                sb.AppendLine(new string('-', 100));
                if (f.Explanation is not null)
                {
                    foreach (var l in ConsoleWriter.Wrap(f.Explanation, 96))
                        sb.AppendLine("    " + l);
                    sb.AppendLine();
                }
                foreach (var (k, v) in f.Data)
                    sb.AppendLine($"    {k,-28}: {v}");
                foreach (var (title, text) in f.Blocks)
                {
                    sb.AppendLine();
                    sb.AppendLine($"    --- {title} ---");
                    foreach (var l in text.Split('\n'))
                        sb.AppendLine("    " + l.TrimEnd());
                }
            }
        }

        sb.AppendLine();
        sb.AppendLine(new string('=', 100));
        sb.AppendLine("FULL DATA (for manual analysis)");
        sb.AppendLine(new string('=', 100));
        foreach (var (title, text) in rep.Sections)
        {
            sb.AppendLine();
            sb.AppendLine(new string('=', 100));
            sb.AppendLine($"== {title}");
            sb.AppendLine(new string('=', 100));
            sb.AppendLine(text);
        }

        if (rep.Errors.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(new string('=', 100));
            sb.AppendLine("SCAN ERRORS");
            sb.AppendLine(new string('=', 100));
            foreach (var e in rep.Errors) sb.AppendLine("  " + e);
        }

        return sb.ToString();
    }
}

internal static class JsonReport
{
    public static string Render(ScanReport rep, int pid, TimeSpan elapsed)
    {
        var root = new JsonObject
        {
            ["tool"] = Program.Tool,
            ["version"] = Program.Version,
            ["timestamp"] = DateTime.Now.ToString("O"),
            ["pid"] = pid,
            ["machine"] = Environment.MachineName,
            ["user"] = Environment.UserName,
            ["os"] = Environment.OSVersion.VersionString,
            ["elapsedSeconds"] = Math.Round(elapsed.TotalSeconds, 2),
            ["summary"] = new JsonObject
            {
                ["critical"] = rep.Count(Severity.Critical),
                ["high"] = rep.Count(Severity.High),
                ["medium"] = rep.Count(Severity.Medium),
                ["low"] = rep.Count(Severity.Low),
                ["info"] = rep.Count(Severity.Info),
            },
        };

        var arr = new JsonArray();
        foreach (var f in rep.Findings.OrderByDescending(x => x.Severity))
        {
            var data = new JsonObject();
            foreach (var (k, v) in f.Data) data[k] = v;
            var blocks = new JsonObject();
            foreach (var (t, txt) in f.Blocks) blocks[t] = txt;
            arr.Add(new JsonObject
            {
                ["severity"] = f.Severity.ToString(),
                ["category"] = f.Category,
                ["title"] = f.Title,
                ["explanation"] = f.Explanation,
                ["data"] = data,
                ["blocks"] = blocks,
            });
        }
        root["findings"] = arr;

        var sections = new JsonObject();
        foreach (var (t, txt) in rep.Sections) sections[t] = txt;
        root["sections"] = sections;

        var errs = new JsonArray();
        foreach (var e in rep.Errors) errs.Add((JsonNode)e);
        root["errors"] = errs;

        return root.ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });
    }
}
