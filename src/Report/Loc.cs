using System.Text.RegularExpressions;

namespace AgentScan.Report;

internal static class Loc
{
    private const char Open = '\u0001';
    private const char Sep = '\u0002';
    private const char Close = '\u0003';

    private static readonly Regex Pair = new(
        "\u0001([^\u0001\u0002\u0003]*)\u0002([^\u0001\u0002\u0003]*)\u0003",
        RegexOptions.Compiled);

    public static string L(string en, string es) => $"{Open}{en}{Sep}{es}{Close}";

    public static string Resolve(string? s, string lang)
    {
        if (string.IsNullOrEmpty(s) || s.IndexOf(Open) < 0) return s ?? "";
        int group = lang == "es" ? 2 : 1;
        string prev;
        do
        {
            prev = s;
            s = Pair.Replace(s, m => m.Groups[group].Value);
        } while (s != prev && s.IndexOf(Open) >= 0);
        return s.Replace(Open.ToString(), "").Replace(Sep.ToString(), "").Replace(Close.ToString(), "");
    }

    public static string En(string? s) => Resolve(s, "en");

    public static ScanReport Localize(ScanReport src, string lang)
    {
        var r = new ScanReport();
        foreach (var f in src.Findings)
        {
            var nf = new Finding
            {
                Category = Resolve(f.Category, lang),
                Title = Resolve(f.Title, lang),
                Severity = f.Severity,
                Explanation = f.Explanation is null ? null : Resolve(f.Explanation, lang),
            };
            foreach (var (k, v) in f.Data) nf.Data.Add((Resolve(k, lang), Resolve(v, lang)));
            foreach (var (t, x) in f.Blocks) nf.Blocks.Add((Resolve(t, lang), Resolve(x, lang)));
            r.Findings.Add(nf);
        }
        foreach (var (t, x) in src.Sections) r.Sections.Add((Resolve(t, lang), Resolve(x, lang)));
        foreach (var e in src.Errors) r.Errors.Add(Resolve(e, lang));
        foreach (var (k, v) in src.Meta) r.Meta.Add((Resolve(k, lang), Resolve(v, lang)));
        return r;
    }
}
