using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using Detector.Amsi;
using Detector.Heuristics;
using Detector.Model;
using Detector.PowerShell;
using Detector.Process;
using Detector.Reporting;
using Detector.Scanning;
using Detector.Watch;
using SysProcess = System.Diagnostics.Process;

namespace Detector.Gui;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly AmsiScanner? _amsi;
    private readonly FileScanEngine _fileEngine;
    private readonly RunPeScanner _runpe = new();
    private readonly GuiDetectionSink _guiSink;
    private readonly FilteringSink _filtering;
    private CancellationTokenSource? _watchCts;

    public ObservableCollection<DetectionRow> Results { get; } = new();
    public ObservableCollection<ProcRow> Processes { get; } = new();

    /// The sink findings flow through: the false-positive filter wraps the GUI
    /// sink unless the user turned filtering off.
    private IDetectionSink Sink => FilterFps ? _filtering : _guiSink;

    public MainViewModel()
    {
        try { _amsi = new AmsiScanner("Detector.Gui"); AmsiOk = true; }
        catch { _amsi = null; AmsiOk = false; }
        _fileEngine = new FileScanEngine(_amsi);
        _guiSink = new GuiDetectionSink(AddDetectionRow, SetStatus, AddTrace);
        _filtering = new FilteringSink(_guiSink);
        AmsiStatus = AmsiOk ? "AMSI active" : "AMSI: no provider available";
        IsAdmin = CheckAdmin();

        ScanFileCommand = new RelayCommand(ScanFile, () => !Busy);
        ScanFolderCommand = new RelayCommand(ScanFolder, () => !Busy);
        ScanPsCommand = new RelayCommand(ScanPs, () => !Busy);
        SelftestCommand = new RelayCommand(Selftest, () => !Busy);
        RefreshProcCommand = new RelayCommand(RefreshProcesses, () => !Busy);
        ScanSelectedProcCommand = new RelayCommand(ScanSelectedProc, () => !Busy && SelectedProcess != null);
        ScanAllProcCommand = new RelayCommand(ScanAllProc, () => !Busy);
        ToggleWatchCommand = new RelayCommand(ToggleWatch);
        ClearCommand = new RelayCommand(() => { Results.Clear(); RecomputeSummary(); }, () => Results.Count > 0);
        ExportCommand = new RelayCommand(Export, () => Results.Count > 0);

        RefreshProcesses();
        RecomputeSummary();
    }

    private bool _busy;
    public bool Busy { get => _busy; set { _busy = value; OnChanged(); CommandManager.InvalidateRequerySuggested(); } }

    public bool AmsiOk { get; }
    public string AmsiStatus { get; }
    public Brush AmsiBrush => AmsiOk ? Rgb(0x2E, 0x7D, 0x32) : Rgb(0x8B, 0x30, 0x30);

    public bool IsAdmin { get; }
    public string AdminStatus => IsAdmin ? "Administrator" : "Limited (not elevated)";
    public Brush AdminBrush => IsAdmin ? Rgb(0x2E, 0x7D, 0x32) : Rgb(0x7A, 0x66, 0x2E);

    private bool _aggressive;
    public bool Aggressive { get => _aggressive; set { _aggressive = value; OnChanged(); } }

    private bool _filterFps = true;
    public bool FilterFps { get => _filterFps; set { _filterFps = value; OnChanged(); } }

    private bool _advanced;
    public bool Advanced { get => _advanced; set { _advanced = value; OnChanged(); } }

    private bool _isWatching;
    public bool IsWatching { get => _isWatching; set { _isWatching = value; OnChanged(); OnChanged(nameof(WatchButtonText)); } }
    public string WatchButtonText => IsWatching ? "■ Stop monitoring" : "▶ Start monitoring";

    private ProcRow? _selectedProcess;
    public ProcRow? SelectedProcess { get => _selectedProcess; set { _selectedProcess = value; OnChanged(); CommandManager.InvalidateRequerySuggested(); } }

    private string _summary = "";
    public string Summary { get => _summary; set { _summary = value; OnChanged(); } }

    private string _status = "Ready. Drop files onto this window or choose an action above.";
    public string Status { get => _status; set { _status = value; OnChanged(); } }

    public ICommand ScanFileCommand { get; }
    public ICommand ScanFolderCommand { get; }
    public ICommand ScanPsCommand { get; }
    public ICommand SelftestCommand { get; }
    public ICommand RefreshProcCommand { get; }
    public ICommand ScanSelectedProcCommand { get; }
    public ICommand ScanAllProcCommand { get; }
    public ICommand ToggleWatchCommand { get; }
    public ICommand ClearCommand { get; }
    public ICommand ExportCommand { get; }

    private void ScanFile()
    {
        var dlg = new OpenFileDialog { Title = "Scan files", Multiselect = true };
        if (dlg.ShowDialog() != true) return;
        var files = dlg.FileNames;
        RunAsync(() => { foreach (var f in files) foreach (var d in _fileEngine.ScanFile(f)) Sink.Report(d); });
    }

    private void ScanFolder()
    {
        var dlg = new OpenFolderDialog { Title = "Scan folder" };
        if (dlg.ShowDialog() != true) return;
        var folder = dlg.FolderName;
        RunAsync(() => { foreach (var d in _fileEngine.ScanDirectory(folder)) Sink.Report(d); });
    }

    private void ScanPs()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Scan PowerShell script",
            Filter = "PowerShell (*.ps1;*.psm1)|*.ps1;*.psm1|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;
        var path = dlg.FileName;
        RunAsync(() =>
        {
            string script;
            try { script = File.ReadAllText(path); }
            catch (Exception ex) { Sink.Report(new Detection("PowerShell", path, Severity.Low, Verdict.Error, "io.read", ex.Message)); return; }
            foreach (var d in new PowerShellScanner(_amsi).Scan(script, path)) Sink.Report(d);
        });
    }

    private void Selftest()
    {
        RunAsync(() =>
        {
            const string amsiTest = "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386";
            if (_amsi is not null) Sink.Report(_amsi.ScanString(amsiTest, "selftest:amsi", "selftest"));
            var eicar = Encoding.ASCII.GetBytes(ContentHeuristics.EicarSignature);
            if (ContentHeuristics.LooksLikeEicar(eicar))
                Sink.Report(new Detection("Heuristics", "selftest:eicar", Severity.High, Verdict.Malicious,
                    "heuristic.eicar", "EICAR test signature detected."));
            if (_amsi is not null) Sink.Report(_amsi.Scan(eicar, "selftest:eicar", "eicar.txt"));
            SetStatus(_amsi is null
                ? "Self-test: heuristic pipeline OK (AMSI is not testable because no provider is available)."
                : "Self-test complete.");
        });
    }

    private void ScanSelectedProc()
    {
        var p = SelectedProcess;
        if (p is null) return;
        bool agg = Aggressive;
        RunAsync(() =>
        {
            try { foreach (var d in _runpe.ScanProcess(p.Pid, p.Name, agg)) Sink.Report(d); }
            catch (UnauthorizedAccessException)
            {
                Sink.Report(new Detection("RunPE", $"{p.Name} (pid {p.Pid})", Severity.Low, Verdict.Error,
                    "proc.access-denied", "Access denied. Run as Administrator for fuller coverage."));
            }
        });
    }

    private void ScanAllProc()
    {
        bool agg = Aggressive;
        RunAsync(() =>
        {
            var findings = _runpe.ScanAll(out int skipped, agg);
            foreach (var d in findings) Sink.Report(d);
            SetStatus(skipped > 0
                ? $"Scanned all processes; skipped {skipped} because access was denied. Run elevated for fuller coverage."
                : "Scanned all processes.");
        });
    }

    private void ToggleWatch()
    {
        if (IsWatching) { _watchCts?.Cancel(); return; }
        var sink = Sink;
        _watchCts = new CancellationTokenSource();
        var token = _watchCts.Token;
        IsWatching = true;

        // Prefer the richer ETW sensor when elevated; otherwise fall back to
        // polling. Both implement IRealtimeMonitor.
        bool etw = EtwSensor.IsElevated();
        IRealtimeMonitor monitor = etw ? new EtwSensor(sink, _amsi) : new WatchService(sink, _amsi);
        SetStatus(etw
            ? "Real-time: ETW sensor active (processes, DLL loads, and PowerShell)."
            : "Real-time: polling mode (run elevated for ETW coverage).");

        Task.Run(() =>
        {
            try { monitor.Run(token); }
            catch (Exception ex) { SetStatus("Monitoring error: " + ex.Message); }
            finally
            {
                (monitor as IDisposable)?.Dispose();
                Application.Current?.Dispatcher.Invoke(() => IsWatching = false);
            }
        });
    }

    private void RefreshProcesses()
    {
        var rows = new List<ProcRow>();
        foreach (var p in SysProcess.GetProcesses())
        {
            try { rows.Add(new ProcRow { Pid = p.Id, Name = p.ProcessName }); }
            catch { }
            finally { p.Dispose(); }
        }
        Processes.Clear();
        foreach (var r in rows.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase))
            Processes.Add(r);
        SetStatus($"{Processes.Count} running processes.");
    }

    private void Export()
    {
        var dlg = new SaveFileDialog
        {
            Title = "Export results as JSONL",
            Filter = "JSON Lines (*.jsonl)|*.jsonl",
            FileName = "detections.jsonl"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            using var w = new StreamWriter(dlg.FileName);
            foreach (var r in Results)
                w.WriteLine(JsonSerializer.Serialize(new { r.Time, r.Source, r.Verdict, r.Severity, r.Rule, r.Target, r.Details }));
            SetStatus($"Exported: {dlg.FileName}");
        }
        catch (Exception ex) { SetStatus("Export error: " + ex.Message); }
    }

    public void OnFilesDropped(string[] paths)
    {
        RunAsync(() =>
        {
            foreach (var p in paths)
            {
                if (Directory.Exists(p)) foreach (var d in _fileEngine.ScanDirectory(p)) Sink.Report(d);
                else foreach (var d in _fileEngine.ScanFile(p)) Sink.Report(d);
            }
        });
    }

    public void Cleanup()
    {
        _watchCts?.Cancel();
        _amsi?.Dispose();
    }

    private async void RunAsync(Action work)
    {
        Busy = true;
        SetStatus("Scanning...");
        try { await Task.Run(work); }
        catch (Exception ex) { SetStatus("Error: " + ex.Message); }
        finally { Busy = false; if (Status == "Scanning...") SetStatus("Finished."); }
    }

    private void AddDetectionRow(Detection d)
    {
        var disp = Application.Current?.Dispatcher;
        if (disp is null) return;
        disp.Invoke(() =>
        {
            Results.Add(DetectionRow.From(d, DateTime.Now.ToString("HH:mm:ss")));
            RecomputeSummary();
        });
    }

    // Keep raw telemetry visually distinct from actual findings.
    private void AddTrace(TraceLevel level, string message)
    {
        if (!Advanced) return;
        var disp = Application.Current?.Dispatcher;
        if (disp is null) return;
        disp.Invoke(() => Results.Add(DetectionRow.Trace(DateTime.Now.ToString("HH:mm:ss"), message)));
    }

    private void SetStatus(string msg)
        => Application.Current?.Dispatcher.Invoke(() => Status = msg);

    private void RecomputeSummary()
    {
        int c = 0, s = 0, m = 0, e = 0;
        foreach (var r in Results)
            switch (r.Verdict)
            {
                case "Clean": c++; break;
                case "Suspicious": s++; break;
                case "Malicious": m++; break;
                case "Error": e++; break;
            }
        Summary = $"clean {c}   suspicious {s}   malicious {m}   error {e}   (total {Results.Count})";
        CommandManager.InvalidateRequerySuggested();
    }

    private static bool CheckAdmin()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static Brush Rgb(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
