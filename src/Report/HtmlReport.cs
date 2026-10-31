using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Unicode;

namespace AgentScan.Report;

internal static class HtmlReport
{
    private static JsonSerializerOptions JsonOpts() => new()
    {
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All),
        WriteIndented = false,
    };

    private const int MaxSectionChars = 600_000;

    public static string Render(ScanReport rep, int pid, TimeSpan elapsed)
    {
        var sb = new StringBuilder(1 << 20);
        sb.Append(Head);
        sb.Append(Body);
        sb.Append("<script id=\"mcdata\" type=\"application/json\">");
        var all = new JsonObject
        {
            ["en"] = BuildPayload(Loc.Localize(rep, "en"), pid, elapsed),
            ["es"] = BuildPayload(Loc.Localize(rep, "es"), pid, elapsed),
        };
        sb.Append(all.ToJsonString(JsonOpts()));
        sb.Append("</script>\n<script>");
        sb.Append(Script);
        sb.Append("</script>\n</body>\n</html>\n");
        return sb.ToString();
    }

    private static JsonObject BuildPayload(ScanReport rep, int pid, TimeSpan elapsed)
    {
        var order = new[] { Severity.Critical, Severity.High, Severity.Medium,
                            Severity.Low, Severity.Info };

        var findings = new JsonArray();
        int n = 0;
        foreach (var sev in order)
        {
            foreach (var f in rep.Findings.Where(x => x.Severity == sev))
            {
                n++;
                var data = new JsonArray();
                foreach (var (k, v) in f.Data)
                    data.Add(new JsonArray((JsonNode)k, (JsonNode)v));

                var blocks = new JsonArray();
                foreach (var (t, txt) in f.Blocks)
                    blocks.Add(new JsonArray((JsonNode)t, (JsonNode)txt));

                findings.Add(new JsonObject
                {
                    ["n"] = n,
                    ["sev"] = (int)f.Severity,
                    ["cat"] = f.Category,
                    ["title"] = f.Title,
                    ["expl"] = f.Explanation ?? "",
                    ["data"] = data,
                    ["blocks"] = blocks,
                });
            }
        }

        var sections = new JsonArray();
        foreach (var (title, text) in rep.Sections)
        {
            bool cut = text.Length > MaxSectionChars;
            sections.Add(new JsonObject
            {
                ["title"] = title,
                ["text"] = cut ? text[..MaxSectionChars] : text,
                ["cut"] = cut,
                ["size"] = text.Length,
            });
        }

        var meta = new JsonArray();
        foreach (var (k, v) in rep.Meta)
            meta.Add(new JsonArray((JsonNode)k, (JsonNode)v));

        var errors = new JsonArray();
        foreach (var e in rep.Errors) errors.Add((JsonNode)e);

        return new JsonObject
        {
            ["tool"] = Program.Tool,
            ["version"] = Program.Version,
            ["pid"] = pid,
            ["generated"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            ["elapsed"] = Math.Round(elapsed.TotalSeconds, 1),
            ["machine"] = Environment.MachineName,
            ["user"] = Environment.UserName,
            ["os"] = Environment.OSVersion.VersionString,
            ["meta"] = meta,
            ["summary"] = new JsonObject
            {
                ["4"] = rep.Count(Severity.Critical),
                ["3"] = rep.Count(Severity.High),
                ["2"] = rep.Count(Severity.Medium),
                ["1"] = rep.Count(Severity.Low),
                ["0"] = rep.Count(Severity.Info),
            },
            ["findings"] = findings,
            ["sections"] = sections,
            ["errors"] = errors,
        };
    }

    private const string Head = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentScan — report</title>
<style>
:root{
  --bg:#0f1216; --bg2:#161a20; --bg3:#1d222a; --line:#272d37;
  --fg:#e6e9ef; --fg2:#a4adbb; --fg3:#6b7482;
  --crit:#f0454b; --high:#f59f00; --med:#22b8cf; --low:#7c8695; --info:#5f6b7a;
  --ok:#37b24d; --accent:#4c8dff;
  --mono:"Cascadia Mono",Consolas,"SF Mono",Menlo,monospace;
}
:root[data-theme="light"]{
  --bg:#f4f6f9; --bg2:#ffffff; --bg3:#eef1f5; --line:#d7dde5;
  --fg:#12161c; --fg2:#4a5462; --fg3:#79838f;
  --crit:#d0323a; --high:#b56a00; --med:#0b7285; --low:#5c6570; --info:#6b7480;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--fg); font:14px/1.55 -apple-system,"Segoe UI",Roboto,sans-serif;
  -webkit-font-smoothing:antialiased;
}
a{color:var(--accent)}
.wrap{max-width:1500px;margin:0 auto;padding:0 20px 80px}

header{border-bottom:1px solid var(--line);background:var(--bg2)}
.hd{max-width:1500px;margin:0 auto;padding:18px 20px;display:flex;gap:20px;
    align-items:flex-start;flex-wrap:wrap}
.brand{font-size:19px;font-weight:650;letter-spacing:.2px}
.brand small{color:var(--fg3);font-weight:400;font-size:12px;margin-left:8px}
.hd-right{margin-left:auto;display:flex;gap:8px;align-items:center}
.btn{background:var(--bg3);color:var(--fg2);border:1px solid var(--line);border-radius:7px;
     padding:6px 11px;font-size:12.5px;cursor:pointer;font-family:inherit}
.btn:hover{color:var(--fg);border-color:var(--fg3)}

.verdict{padding:12px 16px;border-radius:10px;border:1px solid var(--line);
         display:flex;gap:12px;align-items:center;font-size:14.5px;margin:18px 0}
.verdict b{font-weight:650}
.verdict.red{background:rgba(240,69,75,.10);border-color:rgba(240,69,75,.45)}
.verdict.yellow{background:rgba(245,159,0,.10);border-color:rgba(245,159,0,.45)}
.verdict.green{background:rgba(55,178,77,.10);border-color:rgba(55,178,77,.40)}
.verdict .dot{width:10px;height:10px;border-radius:50%;flex:none}
.verdict.red .dot{background:var(--crit)} .verdict.yellow .dot{background:var(--high)}
.verdict.green .dot{background:var(--ok)}
.verdict span.note{color:var(--fg2);font-size:13px}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}
.stat{background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:11px 13px;
      cursor:pointer;transition:.12s;border-left-width:3px}
.stat:hover{border-color:var(--fg3)}
.stat.off{opacity:.4}
.stat .num{font-size:23px;font-weight:650;line-height:1.15}
.stat .lbl{font-size:11.5px;color:var(--fg2);text-transform:uppercase;letter-spacing:.5px}
.s4{border-left-color:var(--crit)} .s4 .num{color:var(--crit)}
.s3{border-left-color:var(--high)} .s3 .num{color:var(--high)}
.s2{border-left-color:var(--med)}  .s2 .num{color:var(--med)}
.s1{border-left-color:var(--low)}  .s1 .num{color:var(--low)}
.s0{border-left-color:var(--info)} .s0 .num{color:var(--info)}

.meta{background:var(--bg2);border:1px solid var(--line);border-radius:10px;margin:16px 0}
.meta summary{padding:11px 14px;cursor:pointer;font-weight:600;font-size:13.5px;user-select:none}
.meta summary::marker{color:var(--fg3)}
.meta .in{padding:0 14px 13px;display:grid;grid-template-columns:minmax(160px,220px) 1fr;
          gap:5px 16px;font-size:13px}
.meta .k{color:var(--fg2)}
.meta .v{font-family:var(--mono);font-size:12.5px;word-break:break-word;white-space:pre-wrap}

.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin:20px 0 0}
.tab{padding:9px 15px;cursor:pointer;color:var(--fg2);font-size:13.5px;border:1px solid transparent;
     border-bottom:none;border-radius:8px 8px 0 0}
.tab:hover{color:var(--fg)}
.tab.act{background:var(--bg2);border-color:var(--line);color:var(--fg);font-weight:600}
.tab .c{color:var(--fg3);font-size:12px;margin-left:5px}

.bar{position:sticky;top:0;z-index:20;background:var(--bg);padding:12px 0 10px;
     border-bottom:1px solid var(--line);margin-bottom:14px}
.bar .row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.search{flex:1;min-width:240px;background:var(--bg2);border:1px solid var(--line);border-radius:8px;
        padding:8px 11px;color:var(--fg);font-size:13.5px;font-family:inherit}
.search:focus{outline:none;border-color:var(--accent)}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}
.chip{background:var(--bg2);border:1px solid var(--line);border-radius:20px;padding:4px 11px;
      font-size:12px;cursor:pointer;color:var(--fg2);user-select:none}
.chip:hover{border-color:var(--fg3);color:var(--fg)}
.chip.on{background:var(--accent);border-color:var(--accent);color:#fff}
.chip .n{opacity:.65;margin-left:5px}
.hint{color:var(--fg3);font-size:12px;margin-top:8px}

.card{background:var(--bg2);border:1px solid var(--line);border-left-width:3px;border-radius:10px;
      margin-bottom:9px;overflow:hidden}
.card.c4{border-left-color:var(--crit)} .card.c3{border-left-color:var(--high)}
.card.c2{border-left-color:var(--med)}  .card.c1{border-left-color:var(--low)}
.card.c0{border-left-color:var(--info)}
.chd{display:flex;gap:11px;align-items:flex-start;padding:11px 14px;cursor:pointer}
.chd:hover{background:var(--bg3)}
.badge{font-size:10.5px;font-weight:700;letter-spacing:.6px;padding:3px 7px;border-radius:5px;
       flex:none;margin-top:1px;white-space:nowrap}
.b4{background:rgba(240,69,75,.16);color:var(--crit)}
.b3{background:rgba(245,159,0,.16);color:var(--high)}
.b2{background:rgba(34,184,207,.14);color:var(--med)}
.b1{background:rgba(124,134,149,.16);color:var(--low)}
.b0{background:rgba(95,107,122,.16);color:var(--info)}
.cat{font-size:11px;color:var(--fg3);border:1px solid var(--line);border-radius:5px;
     padding:2px 7px;flex:none;margin-top:1px}
.ttl{flex:1;font-size:13.8px;line-height:1.45;word-break:break-word}
.idx{color:var(--fg3);font-size:11.5px;flex:none;margin-top:2px;font-family:var(--mono)}
.cbody{padding:0 14px 13px;border-top:1px solid var(--line);display:none}
.card.open .cbody{display:block}
.expl{color:var(--fg2);font-size:13px;line-height:1.6;margin:11px 0;padding-left:11px;
      border-left:2px solid var(--line)}
table.kv{width:100%;border-collapse:collapse;font-size:12.5px;margin:9px 0}
table.kv td{padding:4px 8px;vertical-align:top;border-bottom:1px solid var(--line)}
table.kv td.k{color:var(--fg2);width:270px;word-break:break-word}
table.kv td.v{font-family:var(--mono);white-space:pre-wrap;word-break:break-word}
.blk{margin:9px 0;border:1px solid var(--line);border-radius:8px;background:var(--bg3)}
.blk summary{padding:7px 11px;cursor:pointer;font-size:12.5px;color:var(--fg2);user-select:none}
.blk summary:hover{color:var(--fg)}
.blk pre{margin:0;padding:11px;overflow-x:auto;font-family:var(--mono);font-size:12px;
         line-height:1.45;white-space:pre;border-top:1px solid var(--line)}
mark{background:rgba(76,141,255,.32);color:inherit;border-radius:2px}

.sec-wrap{display:grid;grid-template-columns:300px 1fr;gap:16px;align-items:start}
.sec-nav{position:sticky;top:64px;max-height:calc(100vh - 90px);overflow:auto;
         background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:7px}
.sec-nav div{padding:7px 10px;border-radius:6px;cursor:pointer;font-size:12.5px;color:var(--fg2);
             word-break:break-word}
.sec-nav div:hover{background:var(--bg3);color:var(--fg)}
.sec-nav div.act{background:var(--accent);color:#fff}
.sec-nav div .sz{float:right;font-size:11px;opacity:.6}
.sec-body{background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:14px;
          min-width:0}
.sec-body h3{margin:0 0 10px;font-size:15px}
.sec-body pre{margin:0;overflow-x:auto;font-family:var(--mono);font-size:12px;line-height:1.45;
              white-space:pre;max-height:75vh;overflow-y:auto}
.cutwarn{color:var(--high);font-size:12.5px;margin-bottom:9px}

.empty{color:var(--fg3);text-align:center;padding:50px 0;font-size:14px}
.err{background:var(--bg2);border:1px solid var(--line);border-left:3px solid var(--high);
     border-radius:8px;padding:10px 13px;margin-bottom:7px;font-family:var(--mono);font-size:12px;
     white-space:pre-wrap;word-break:break-word}
.lang{display:inline-flex;gap:0;margin-right:6px}
.lang .btn{border-radius:0}
.lang .btn:first-child{border-radius:6px 0 0 6px}
.lang .btn:last-child{border-radius:0 6px 6px 0}
.lang .btn.on{background:var(--accent);border-color:var(--accent);color:#fff}
footer{color:var(--fg3);font-size:12px;text-align:center;padding:26px 0}
@media(max-width:900px){.sec-wrap{grid-template-columns:1fr}.sec-nav{position:static;max-height:260px}}
</style>
</head>
<body>
""";

    private const string Body = """
<header>
  <div class="hd">
    <div>
      <div class="brand">AgentScan <small id="hd-sub"></small></div>
      <div id="hd-target" style="color:var(--fg2);font-size:12.5px;margin-top:3px"></div>
    </div>
    <div class="hd-right">
      <span class="lang"><button class="btn" id="lang-en">EN</button><button class="btn" id="lang-es">ES</button></span>
      <button class="btn" id="btn-expand" data-i18n="btn.expand"></button>
      <button class="btn" id="btn-collapse" data-i18n="btn.collapse"></button>
      <button class="btn" id="btn-theme" data-i18n="btn.theme"></button>
    </div>
  </div>
</header>

<div class="wrap">
  <div id="verdict"></div>
  <div class="stats" id="stats"></div>

  <details class="meta" id="meta-box">
    <summary data-i18n="meta.summary"></summary>
    <div class="in" id="meta"></div>
  </details>

  <details class="meta">
    <summary data-i18n="howto.summary"></summary>
    <div class="in" style="grid-template-columns:1fr">
      <div style="color:var(--fg2);font-size:13px;line-height:1.65" data-i18n-html="howto.body"></div>
    </div>
  </details>

  <div class="tabs" id="tabs">
    <div class="tab act" data-tab="find"><span data-i18n="tab.find"></span> <span class="c" id="t-find"></span></div>
    <div class="tab" data-tab="sect"><span data-i18n="tab.sect"></span> <span class="c" id="t-sect"></span></div>
    <div class="tab" data-tab="errs"><span data-i18n="tab.errs"></span> <span class="c" id="t-errs"></span></div>
  </div>

  <div id="pane-find">
    <div class="bar">
      <div class="row">
        <input class="search" id="q" data-i18n-ph="ph.find">
        <button class="btn" id="btn-clear" data-i18n="btn.clear"></button>
      </div>
      <div class="chips" id="cats"></div>
      <div class="hint" id="hint"></div>
    </div>
    <div id="findings"></div>
  </div>

  <div id="pane-sect" style="display:none">
    <div class="bar">
      <div class="row">
        <input class="search" id="qs" data-i18n-ph="ph.sect">
      </div>
      <div class="hint" id="hint-s"></div>
    </div>
    <div class="sec-wrap">
      <div class="sec-nav" id="sec-nav"></div>
      <div class="sec-body" id="sec-body"></div>
    </div>
  </div>

  <div id="pane-errs" style="display:none">
    <div id="errors"></div>
  </div>

  <footer id="foot"></footer>
</div>
""";

    private const string Script = """
const ALL = JSON.parse(document.getElementById('mcdata').textContent);
let LANG = 'en';
try {
  const h = (location.hash || '').replace('#', '');
  const s = localStorage.getItem('agentscan-lang');
  LANG = (h === 'es' || h === 'en') ? h : (s === 'es' ? 'es' : 'en');
} catch (e) {}
const D = ALL[LANG] || ALL.en;
document.documentElement.lang = LANG;

const I18N = {
  en: {
    'title': 'AgentScan — report',
    'btn.expand': 'Expand all', 'btn.collapse': 'Collapse all', 'btn.theme': 'Theme',
    'btn.clear': 'Reset filters',
    'meta.summary': 'Process and scan details',
    'howto.summary': 'How to read this report',
    'howto.body':
      '<p style="margin-top:0"><b>The scanner does not deliver a verdict for a human.</b> It shows what it found in the process memory and explains the mechanics of every finding. The decision is made on the whole picture: a single medium finding is almost never proof, while several consistent ones are.</p>' +
      '<p><b>Severity.</b> <span style="color:var(--crit)">CRITICAL</span> — a state that never occurs in a clean process; ' +
      '<span style="color:var(--high)">HIGH</span> — a strong anomaly that needs an explanation; ' +
      '<span style="color:var(--med)">MEDIUM</span> — needs manual review, can also be normal; ' +
      '<span style="color:var(--low)">LOW</span> — a weak sign, useful next to others; ' +
      '<span style="color:var(--info)">INFO</span> — reference data recorded for the log.</p>' +
      '<p><b>About a negative result.</b> No findings does not prove the process is clean: some traces disappear when memory is overwritten. That is why the report always has full data sections — worth reviewing even with a zero count.</p>' +
      '<p><b>The «Full data» tab</b> holds the data the findings were made from: JVMTI environments, VM flags, event logs, runtime properties. It also contains whatever did not make it into any finding.</p>' +
      '<p><b>Search</b> looks through finding titles, explanations and data fields, and on the «Full data» tab through section contents. The <b>/</b> key puts the cursor into the search box.</p>',
    'tab.find': 'Findings', 'tab.sect': 'Full data', 'tab.errs': 'Scan errors',
    'ph.find': 'Search findings: module name, address, string…',
    'ph.sect': 'Search section contents…',
    'sev.4': 'CRITICAL', 'sev.3': 'HIGH', 'sev.2': 'MEDIUM', 'sev.1': 'LOW', 'sev.0': 'INFO',
    'hd.report': 'report of', 'unit.s': 's',
    'meta.image': 'Image',
    'v.red': 'Signs of foreign code found in the process.',
    'v.red.note': 'Review the critical findings manually: each contains an explanation of the mechanics and raw data. The scanner does not decide for a human.',
    'v.yellow': 'There are anomalies that need manual review.',
    'v.yellow.note': 'No critical signs, but what was found needs an explanation.',
    'v.green': 'No clear traces of agents or JVMTI found.',
    'v.green.note': 'This is not a guarantee of cleanliness: some traces disappear when memory is overwritten. Review the «Full data» tab.',
    'm.os': 'System', 'm.by': 'Scanned by', 'm.dur': 'Scan duration',
    'f.findings': 'findings', 'f.sections': 'full data sections', 'f.errors': 'scan errors',
    'lines': 'lines',
    'empty.find': 'Nothing matches the current filters.',
    'hint.shown': 'Shown', 'hint.of': 'of', 'hint.findings': 'findings',
    'hint.click': '. Click a finding to expand its details.',
    'nav.none': 'No matches',
    'hs.match': 'Sections with a match: ', 'hs.match2': '. The number next to the title is how many times the string occurs in the section.',
    'hs.all': 'Sections: ', 'hs.all2': '. This is the full data the findings were made from.',
    'kb': 'K',
    'sec.none': 'No section selected.',
    'sec.cut': 'Section truncated for HTML (', 'sec.cut2': ' KB). The full text is in the .txt report next to this file.',
    'err.none': 'There were no errors during the scan — all checks ran.',
  },
  es: {
    'title': 'AgentScan — informe',
    'btn.expand': 'Expandir todo', 'btn.collapse': 'Contraer todo', 'btn.theme': 'Tema',
    'btn.clear': 'Restablecer filtros',
    'meta.summary': 'Datos del proceso y de la comprobación',
    'howto.summary': 'Cómo leer este informe',
    'howto.body':
      '<p style="margin-top:0"><b>El escáner no emite un veredicto en lugar de una persona.</b> Muestra lo que encontró en la memoria del proceso y explica la mecánica de cada hallazgo. La decisión se toma con el conjunto: un hallazgo medio casi nunca es una prueba, mientras que varios coherentes entre sí sí lo son.</p>' +
      '<p><b>Gravedad.</b> <span style="color:var(--crit)">CRÍTICO</span>: un estado que nunca ocurre en un proceso limpio; ' +
      '<span style="color:var(--high)">ALTO</span>: una anomalía fuerte que necesita explicación; ' +
      '<span style="color:var(--med)">MEDIO</span>: requiere revisión manual, también puede ser normal; ' +
      '<span style="color:var(--low)">BAJO</span>: un indicio débil, útil junto a otros; ' +
      '<span style="color:var(--info)">INFO</span>: datos de referencia registrados para el informe.</p>' +
      '<p><b>Sobre un resultado negativo.</b> No tener hallazgos no demuestra que el proceso esté limpio: algunos rastros desaparecen al sobrescribirse la memoria. Por eso el informe siempre tiene secciones con datos completos, que conviene revisar incluso con recuento cero.</p>' +
      '<p><b>La pestaña «Datos completos»</b> contiene los datos a partir de los que se hicieron los hallazgos: entornos JVMTI, banderas de la VM, registros de eventos, propiedades del entorno de ejecución. También contiene lo que no entró en ningún hallazgo.</p>' +
      '<p><b>La búsqueda</b> recorre los títulos, las explicaciones y los campos de datos de los hallazgos, y en la pestaña «Datos completos», el contenido de las secciones. La tecla <b>/</b> pone el cursor en la búsqueda.</p>',
    'tab.find': 'Hallazgos', 'tab.sect': 'Datos completos', 'tab.errs': 'Errores del escaneo',
    'ph.find': 'Buscar en hallazgos: nombre de módulo, dirección, cadena…',
    'ph.sect': 'Buscar en el contenido de las secciones…',
    'sev.4': 'CRÍTICO', 'sev.3': 'ALTO', 'sev.2': 'MEDIO', 'sev.1': 'BAJO', 'sev.0': 'INFO',
    'hd.report': 'informe del', 'unit.s': 's',
    'meta.image': 'Imagen',
    'v.red': 'Se encontraron indicios de código ajeno en el proceso.',
    'v.red.note': 'Revise manualmente los hallazgos críticos: cada uno contiene una explicación de la mecánica y datos en bruto. El escáner no decide en lugar de una persona.',
    'v.yellow': 'Hay anomalías que requieren revisión manual.',
    'v.yellow.note': 'No hay indicios críticos, pero lo encontrado necesita explicación.',
    'v.green': 'No se encontraron rastros claros de agentes ni de JVMTI.',
    'v.green.note': 'No es una garantía de limpieza: algunos rastros desaparecen al sobrescribirse la memoria. Revise la pestaña «Datos completos».',
    'm.os': 'Sistema', 'm.by': 'Comprobado por', 'm.dur': 'Duración de la comprobación',
    'f.findings': 'hallazgos', 'f.sections': 'secciones con datos completos', 'f.errors': 'errores del escaneo',
    'lines': 'líneas',
    'empty.find': 'Nada coincide con los filtros actuales.',
    'hint.shown': 'Se muestran', 'hint.of': 'de', 'hint.findings': 'hallazgos',
    'hint.click': '. Haga clic en un hallazgo para ver los detalles.',
    'nav.none': 'Sin coincidencias',
    'hs.match': 'Secciones con coincidencias: ', 'hs.match2': '. El número junto al título indica cuántas veces aparece la cadena en la sección.',
    'hs.all': 'Secciones: ', 'hs.all2': '. Son los datos completos a partir de los que se hicieron los hallazgos.',
    'kb': 'K',
    'sec.none': 'No hay ninguna sección seleccionada.',
    'sec.cut': 'Sección recortada para HTML (', 'sec.cut2': ' KB). El texto completo está en el informe .txt junto a este archivo.',
    'err.none': 'No hubo errores durante el escaneo: todas las comprobaciones se ejecutaron.',
  },
};
const T = k => (I18N[LANG] && I18N[LANG][k]) || I18N.en[k] || k;

document.title = T('title');
document.querySelectorAll('[data-i18n]').forEach(el => el.textContent = T(el.dataset.i18n));
document.querySelectorAll('[data-i18n-html]').forEach(el => el.innerHTML = T(el.dataset.i18nHtml));
document.querySelectorAll('[data-i18n-ph]').forEach(el => el.placeholder = T(el.dataset.i18nPh));
['en', 'es'].forEach(l => {
  const b = document.getElementById('lang-' + l);
  b.classList.toggle('on', l === LANG);
  b.onclick = () => {
    if (l === LANG) return;
    try { localStorage.setItem('agentscan-lang', l); } catch (e) {}
    location.hash = l;
    location.reload();
  };
});
const SEV = {4:[T('sev.4'),'crit'],3:[T('sev.3'),'high'],2:[T('sev.2'),'med'],
             1:[T('sev.1'),'low'],0:[T('sev.0'),'info']};
const esc = s => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

D.findings.forEach(f => {
  f.idx = (f.title + ' ' + f.cat + ' ' + f.expl + ' ' +
           f.data.map(d => d[0] + ' ' + d[1]).join(' ') + ' ' +
           f.blocks.map(b => b[0]).join(' ')).toLowerCase();
});

const state = {
  sev: new Set([4,3,2,1,0]),
  cats: new Set(),
  q: '',
  tab: 'find',
  sec: 0,
};

document.getElementById('hd-sub').textContent =
  D.version + ' · ' + T('hd.report') + ' ' + D.generated + ' · ' + D.elapsed + ' ' + T('unit.s');
document.getElementById('hd-target').textContent =
  'PID ' + D.pid + ' · ' + (D.meta.find(m => m[0] === T('meta.image')) || ['', ''])[1] +
  ' · ' + D.machine + '\\' + D.user;

const crit = D.summary['4'], high = D.summary['3'], med = D.summary['2'];
const v = document.getElementById('verdict');
if (crit > 0) {
  v.className = 'verdict red';
  v.innerHTML = '<span class="dot"></span><div><b>' + T('v.red') + '</b>' +
    '<div class="note">' + T('v.red.note') + '</div></div>';
} else if (high > 0) {
  v.className = 'verdict yellow';
  v.innerHTML = '<span class="dot"></span><div><b>' + T('v.yellow') + '</b>' +
    '<div class="note">' + T('v.yellow.note') + '</div></div>';
} else {
  v.className = 'verdict green';
  v.innerHTML = '<span class="dot"></span><div><b>' + T('v.green') + '</b>' +
    '<div class="note">' + T('v.green.note') + '</div></div>';
}

const stats = document.getElementById('stats');
[4,3,2,1,0].forEach(s => {
  const d = document.createElement('div');
  d.className = 'stat s' + s;
  d.dataset.sev = s;
  d.innerHTML = '<div class="num">' + D.summary[s] + '</div><div class="lbl">' + SEV[s][0] + '</div>';
  d.onclick = () => { toggleSev(s); };
  stats.appendChild(d);
});

const meta = document.getElementById('meta');
D.meta.forEach(([k, val]) => {
  meta.insertAdjacentHTML('beforeend',
    '<div class="k">' + esc(k) + '</div><div class="v">' + esc(val) + '</div>');
});
meta.insertAdjacentHTML('beforeend',
  '<div class="k">' + T('m.os') + '</div><div class="v">' + esc(D.os) + '</div>' +
  '<div class="k">' + T('m.by') + '</div><div class="v">' + esc(D.machine + '\\' + D.user) + '</div>' +
  '<div class="k">' + T('m.dur') + '</div><div class="v">' + D.elapsed + ' ' + T('unit.s') + '</div>');

document.getElementById('foot').textContent =
  'AgentScan ' + D.version + ' · ' + T('f.findings') + ': ' + D.findings.length +
  ' · ' + T('f.sections') + ': ' + D.sections.length +
  ' · ' + T('f.errors') + ': ' + D.errors.length;

const catCounts = {};
D.findings.forEach(f => catCounts[f.cat] = (catCounts[f.cat] || 0) + 1);
const catsBox = document.getElementById('cats');
Object.keys(catCounts).sort((a, b) => catCounts[b] - catCounts[a]).forEach(c => {
  const el = document.createElement('div');
  el.className = 'chip';
  el.innerHTML = esc(c) + '<span class="n">' + catCounts[c] + '</span>';
  el.onclick = () => {
    if (state.cats.has(c)) state.cats.delete(c); else state.cats.add(c);
    el.classList.toggle('on');
    render();
  };
  catsBox.appendChild(el);
});

function toggleSev(s) {
  if (state.sev.has(s)) state.sev.delete(s); else state.sev.add(s);
  document.querySelectorAll('.stat').forEach(el => {
    el.classList.toggle('off', !state.sev.has(+el.dataset.sev));
  });
  render();
}

document.getElementById('q').oninput = e => { state.q = e.target.value.toLowerCase(); render(); };
document.getElementById('btn-clear').onclick = () => {
  state.sev = new Set([4,3,2,1,0]);
  state.cats.clear();
  state.q = '';
  document.getElementById('q').value = '';
  document.querySelectorAll('.stat').forEach(el => el.classList.remove('off'));
  document.querySelectorAll('#cats .chip').forEach(el => el.classList.remove('on'));
  render();
};

document.getElementById('btn-expand').onclick =
  () => document.querySelectorAll('#findings .card').forEach(c => c.classList.add('open'));
document.getElementById('btn-collapse').onclick =
  () => document.querySelectorAll('#findings .card').forEach(c => c.classList.remove('open'));

document.getElementById('btn-theme').onclick = () => {
  const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', cur);
  try { localStorage.setItem('agentscan-theme', cur); } catch (e) {}
};
try {
  const t = localStorage.getItem('agentscan-theme');
  if (t) document.documentElement.setAttribute('data-theme', t);
} catch (e) {}

document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
    e.preventDefault();
    (state.tab === 'sect' ? document.getElementById('qs') : document.getElementById('q')).focus();
  }
  if (e.key === 'Escape' && document.activeElement.tagName === 'INPUT') {
    document.activeElement.value = '';
    document.activeElement.dispatchEvent(new Event('input'));
  }
});

document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => {
    state.tab = t.dataset.tab;
    document.querySelectorAll('.tab').forEach(x => x.classList.toggle('act', x === t));
    document.getElementById('pane-find').style.display = state.tab === 'find' ? '' : 'none';
    document.getElementById('pane-sect').style.display = state.tab === 'sect' ? '' : 'none';
    document.getElementById('pane-errs').style.display = state.tab === 'errs' ? '' : 'none';
  };
});
document.getElementById('t-find').textContent = D.findings.length;
document.getElementById('t-sect').textContent = D.sections.length;
document.getElementById('t-errs').textContent = D.errors.length;

function hl(text, q) {
  const s = esc(text);
  if (!q) return s;
  try {
    return s.replace(new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi'),
                     '<mark>$1</mark>');
  } catch (e) { return s; }
}

function cardHtml(f) {
  let h = '<div class="card c' + f.sev + '" data-n="' + f.n + '">';
  h += '<div class="chd"><span class="badge b' + f.sev + '">' + SEV[f.sev][0] + '</span>' +
       '<span class="cat">' + esc(f.cat) + '</span>' +
       '<span class="ttl">' + hl(f.title, state.q) + '</span>' +
       '<span class="idx">#' + f.n + '</span></div>';
  h += '<div class="cbody">';
  if (f.expl) h += '<div class="expl">' + hl(f.expl, state.q) + '</div>';
  if (f.data.length) {
    h += '<table class="kv">';
    f.data.forEach(([k, val]) => {
      h += '<tr><td class="k">' + hl(k, state.q) + '</td><td class="v">' +
           hl(val, state.q) + '</td></tr>';
    });
    h += '</table>';
  }
  f.blocks.forEach(([t, txt]) => {
    h += '<details class="blk"><summary>' + esc(t) + ' — ' + txt.split('\n').length +
         ' ' + T('lines') + '</summary><pre>' + esc(txt) + '</pre></details>';
  });
  h += '</div></div>';
  return h;
}

function render() {
  const list = D.findings.filter(f =>
    state.sev.has(f.sev) &&
    (state.cats.size === 0 || state.cats.has(f.cat)) &&
    (state.q === '' || f.idx.indexOf(state.q) >= 0));

  const box = document.getElementById('findings');
  if (list.length === 0) {
    box.innerHTML = '<div class="empty">' + T('empty.find') + '</div>';
  } else {
    box.innerHTML = list.map(cardHtml).join('');
    box.querySelectorAll('.chd').forEach(h => {
      h.onclick = () => h.parentElement.classList.toggle('open');
    });
    if (list.length <= 40)
      box.querySelectorAll('.card.c4').forEach(c => c.classList.add('open'));
    if (state.q) {
      list.forEach(f => {
        if (f.title.toLowerCase().indexOf(state.q) < 0)
          box.querySelector('.card[data-n="' + f.n + '"]').classList.add('open');
      });
    }
  }

  const bySev = {};
  list.forEach(f => bySev[f.sev] = (bySev[f.sev] || 0) + 1);
  document.getElementById('hint').textContent =
    T('hint.shown') + ' ' + list.length + ' ' + T('hint.of') + ' ' + D.findings.length + ' ' + T('hint.findings') +
    (list.length ? ' (' + [4,3,2,1,0].filter(s => bySev[s])
        .map(s => SEV[s][0].toLowerCase() + ': ' + bySev[s]).join(', ') + ')' : '') +
    T('hint.click');
}

const secNav = document.getElementById('sec-nav');

function countIn(text, q) {
  if (!q) return 0;
  let n = 0, i = 0;
  const low = text.toLowerCase();
  while ((i = low.indexOf(q, i)) >= 0) { n++; i += q.length; }
  return n;
}

function renderNav(q) {
  secNav.innerHTML = '';
  const hits = [];
  D.sections.forEach((s, i) => {
    if (!q) { hits.push([i, 0]); return; }
    const inTitle = s.title.toLowerCase().indexOf(q) >= 0;
    const c = countIn(s.text, q);
    if (inTitle || c > 0) hits.push([i, c]);
  });

  if (q && hits.length && !hits.some(h => h[0] === state.sec)) state.sec = hits[0][0];

  if (hits.length === 0) {
    secNav.innerHTML = '<div style="color:var(--fg3);padding:9px 10px">' + T('nav.none') + '</div>';
  }
  hits.forEach(([i, c]) => {
    const s = D.sections[i];
    const d = document.createElement('div');
    d.className = i === state.sec ? 'act' : '';
    d.innerHTML = esc(s.title) + '<span class="sz">' +
      (q && c ? '×' + c : Math.round(s.size / 1024) + T('kb')) + '</span>';
    d.onclick = () => { state.sec = i; renderNav(q); renderSec(q); };
    secNav.appendChild(d);
  });

  document.getElementById('hint-s').textContent = q
    ? T('hs.match') + hits.length + ' ' + T('hint.of') + ' ' + D.sections.length + T('hs.match2')
    : T('hs.all') + D.sections.length + T('hs.all2');
}

function renderSec(q) {
  const s = D.sections[state.sec];
  const body = document.getElementById('sec-body');
  if (!s) { body.innerHTML = '<div class="empty">' + T('sec.none') + '</div>'; return; }
  let h = '<h3>' + esc(s.title) + '</h3>';
  if (s.cut) h += '<div class="cutwarn">' + T('sec.cut') +
    Math.round(s.size / 1024) + T('sec.cut2') + '</div>';
  h += '<pre>' + hl(s.text, q) + '</pre>';
  body.innerHTML = h;
  const m = body.querySelector('mark');
  if (m) m.scrollIntoView({block: 'center'});
}

document.getElementById('qs').oninput = e => {
  const q = e.target.value.toLowerCase();
  renderNav(q);
  renderSec(q);
};

const errBox = document.getElementById('errors');
errBox.innerHTML = D.errors.length
  ? D.errors.map(e => '<div class="err">' + esc(e) + '</div>').join('')
  : '<div class="empty">' + T('err.none') + '</div>';

render();
renderNav('');
renderSec('');
""";
}
