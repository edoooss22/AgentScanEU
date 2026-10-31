using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using AgentScan.Analysis;
using AgentScan.Report;

namespace AgentScan.Gui;

internal sealed class MainForm : Form
{
    private sealed record ProcItem(int Pid, string Title, long WorkingSet, bool Minecraft)
    {
        public override string ToString() =>
            $"{Pid} {Title} - {WorkingSet / (1024.0 * 1024 * 1024):F2} GB";
    }

    private readonly ComboBox _procs = new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList,
        Dock = DockStyle.Fill,
    };
    private readonly Button _refresh = new() { Text = "Refresh", AutoSize = true };
    private readonly Button _scan = new() { Text = "Scan", AutoSize = true };
    private readonly ProgressBar _bar = new()
    {
        Dock = DockStyle.Fill, Minimum = 0, Maximum = 1000, Height = 22,
    };
    private readonly Label _status = new()
    {
        AutoSize = false, Dock = DockStyle.Fill, Height = 20, AutoEllipsis = true,
        Text = "Select the Minecraft process and press «Scan».",
    };
    private readonly Label _verdict = new()
    {
        AutoSize = false, Dock = DockStyle.Fill, Height = 26, AutoEllipsis = true,
    };
    private readonly Label _counts = new() { AutoSize = true };
    private readonly Button _openFolder = new() { Text = "Result", AutoSize = true, Enabled = false };
    private readonly Button _openBrowser = new() { Text = "In browser", AutoSize = true, Enabled = false };
    private readonly Label _warning = new()
    {
        AutoSize = true, ForeColor = Color.DarkGoldenrod, Visible = false,
        Text = "No administrator rights: only processes of the current user are available.",
    };

    private ScanOutcome? _last;
    private bool _busy;
    private bool _closeWhenDone;
    private int _lastPermille = -1;
    private string _lastText = "";

    public static void RunApp()
    {
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }

    private MainForm()
    {
        Text = $"{Program.Tool} {Program.Version} — Java agents and JVMTI in Minecraft";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        Font = new Font("Segoe UI", 9.5f);
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(640, 300);

        _verdict.Font = new Font(Font, FontStyle.Bold);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, Padding = new Padding(14), ColumnCount = 2, RowCount = 9,
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        for (int i = 0; i < 9; i++) root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        root.Controls.Add(new Label { Text = "Game process:", AutoSize = true }, 0, 0);
        root.SetColumnSpan(root.GetControlFromPosition(0, 0)!, 2);
        root.Controls.Add(_procs, 0, 1);
        root.Controls.Add(_refresh, 1, 1);

        var actions = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 8, 0, 4) };
        actions.Controls.Add(_scan);
        root.Controls.Add(actions, 0, 2);
        root.SetColumnSpan(actions, 2);

        root.Controls.Add(_bar, 0, 3);
        root.SetColumnSpan(_bar, 2);
        root.Controls.Add(_status, 0, 4);
        root.SetColumnSpan(_status, 2);
        root.Controls.Add(_verdict, 0, 5);
        root.SetColumnSpan(_verdict, 2);
        root.Controls.Add(_counts, 0, 6);
        root.SetColumnSpan(_counts, 2);

        var results = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 6, 0, 0) };
        results.Controls.Add(_openFolder);
        results.Controls.Add(_openBrowser);
        root.Controls.Add(results, 0, 7);
        root.SetColumnSpan(results, 2);
        root.Controls.Add(_warning, 0, 8);
        root.SetColumnSpan(_warning, 2);

        Controls.Add(root);

        _refresh.Click += (_, _) => LoadProcesses();
        _scan.Click += async (_, _) => await ScanAsync();
        _openFolder.Click += (_, _) => ShowInFolder();
        _openBrowser.Click += (_, _) => OpenInBrowser();
        FormClosing += OnClosing;
        Scanner.ProgressChanged += OnProgress;

        _warning.Visible = !Core.SelfProcess.HasDebugPrivilege;
        LoadProcesses();
    }

    private void LoadProcesses()
    {
        int? keep = (_procs.SelectedItem as ProcItem)?.Pid;
        var items = new List<ProcItem>();
        foreach (string name in new[] { "javaw", "java" })
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                using (p)
                {
                    try
                    {
                        string title = p.MainWindowTitle;
                        if (string.IsNullOrWhiteSpace(title)) title = $"({name}.exe, no window)";
                        items.Add(new ProcItem(p.Id, title, p.WorkingSet64,
                            title.Contains("Minecraft", StringComparison.OrdinalIgnoreCase)));
                    }
                    catch { }
                }
            }
        }
        items = items.OrderByDescending(i => i.Minecraft)
                     .ThenByDescending(i => i.WorkingSet).ToList();

        _procs.BeginUpdate();
        _procs.Items.Clear();
        foreach (var i in items) _procs.Items.Add(i);
        _procs.EndUpdate();

        if (items.Count == 0)
        {
            _status.Text = "No javaw.exe / java.exe processes found. Start the game and press «Refresh».";
            _scan.Enabled = false;
            return;
        }
        int idx = keep is null ? 0 : Math.Max(0, items.FindIndex(i => i.Pid == keep));
        _procs.SelectedIndex = idx;
        _scan.Enabled = !_busy;
        if (!_busy) _status.Text = $"Processes found: {items.Count}.";
    }

    private async Task ScanAsync()
    {
        if (_procs.SelectedItem is not ProcItem item || _busy) return;

        SetBusy(true);
        _last = null;
        _verdict.Text = "";
        _counts.Text = "";
        _bar.Value = 0;
        _lastPermille = -1;

        var opt = Options.Parse(Array.Empty<string>());
        try
        {
            _last = await Task.Run(() => ScanRunner.Run(item.Pid, opt));
            ShowResult(_last);
        }
        catch (OperationCanceledException)
        {
            _status.Text = "Scan cancelled.";
        }
        catch (Exception ex)
        {
            _verdict.ForeColor = Color.Firebrick;
            _verdict.Text = "Scan failed";
            _status.Text = $"{ex.GetType().Name}: {ex.Message}";
        }
        finally
        {
            SetBusy(false);
            if (_closeWhenDone) Close();
        }
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        _scan.Enabled = !busy && _procs.Items.Count > 0;
        _procs.Enabled = !busy;
        _refresh.Enabled = !busy;
        _openFolder.Enabled = !busy && _last?.HtmlPath is not null;
        _openBrowser.Enabled = !busy && _last?.HtmlPath is not null;
        UseWaitCursor = busy;
    }

    private void OnProgress(double fraction, string text)
    {
        int permille = (int)(fraction * 1000);
        if (permille == _lastPermille && text == _lastText) return;
        _lastPermille = permille;
        _lastText = text;
        if (!IsHandleCreated || IsDisposed) return;
        BeginInvoke(() =>
        {
            _bar.Value = Math.Clamp(permille, _bar.Minimum, _bar.Maximum);
            _status.Text = En(text);
        });
    }

    private void ShowResult(ScanOutcome res)
    {
        var rep = res.Report;
        int crit = rep.Count(Severity.Critical), high = rep.Count(Severity.High);
        int med = rep.Count(Severity.Medium), low = rep.Count(Severity.Low);

        if (crit > 0)
        {
            _verdict.ForeColor = Color.Firebrick;
            _verdict.Text = "Signs of foreign code found in the process";
        }
        else if (high > 0)
        {
            _verdict.ForeColor = Color.DarkOrange;
            _verdict.Text = "There are anomalies that need manual review";
        }
        else
        {
            _verdict.ForeColor = Color.ForestGreen;
            _verdict.Text = "No clear traces of agents or JVMTI found";
        }
        _counts.Text = $"Critical: {crit}   High: {high}   Medium: {med}   Low: {low}   Time: {res.Elapsed.TotalSeconds:F0} s";
        _bar.Value = _bar.Maximum;
        _status.Text = res.HtmlPath is not null
            ? $"Report: {res.HtmlPath}"
            : "Report not written: " + string.Join("; ", res.Errors);
    }

    private void ShowInFolder()
    {
        if (_last?.HtmlPath is not { } path) return;
        try { Process.Start("explorer.exe", $"/select,\"{path}\""); }
        catch (Exception ex) { _status.Text = $"Failed to open the folder: {ex.Message}"; }
    }

    private void OpenInBrowser()
    {
        if (_last?.HtmlPath is not { } path) return;
        try
        {
            var psi = DefaultBrowser(new Uri(path).AbsoluteUri)
                      ?? new ProcessStartInfo(path) { UseShellExecute = true };
            Process.Start(psi);
        }
        catch (Exception ex) { _status.Text = $"Failed to open the browser: {ex.Message}"; }
    }

    private static ProcessStartInfo? DefaultBrowser(string url)
    {
        try
        {
            using var choice = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice");
            if (choice?.GetValue("ProgId") is not string progId || progId.Length == 0) return null;
            using var cmdKey = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(
                $@"{progId}\shell\open\command");
            if (cmdKey?.GetValue(null) is not string cmd || cmd.Length == 0) return null;

            cmd = cmd.Trim();
            string exe, args;
            if (cmd.StartsWith('"'))
            {
                int end = cmd.IndexOf('"', 1);
                if (end < 0) return null;
                exe = cmd[1..end];
                args = cmd[(end + 1)..].Trim();
            }
            else
            {
                int sp = cmd.IndexOf(' ');
                exe = sp < 0 ? cmd : cmd[..sp];
                args = sp < 0 ? "" : cmd[(sp + 1)..].Trim();
            }
            if (!File.Exists(exe)) return null;

            args = args.Contains("%1")
                ? args.Replace("%1", url)
                : (args + " \"" + url + "\"").Trim();
            return new ProcessStartInfo(exe, args) { UseShellExecute = false };
        }
        catch { return null; }
    }

    private void OnClosing(object? sender, FormClosingEventArgs e)
    {
        if (!_busy) { Scanner.ProgressChanged -= OnProgress; return; }
        e.Cancel = true;
        if (_closeWhenDone) return;
        var answer = MessageBox.Show(this,
            "The scan is still running. Stop it and close the window?\n\nThe window will close when the current step finishes.",
            Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (answer != DialogResult.Yes) return;
        _closeWhenDone = true;
        Scanner.CancelRequested = true;
        _status.Text = "Stopping: waiting for the current step to finish…";
    }
}
