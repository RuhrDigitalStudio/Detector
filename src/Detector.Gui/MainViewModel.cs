using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using Detector.Analysis;
using Detector.Model;
using Detector.Process;
using Detector.Reporting;
using Detector.Scanning;
using Detector.Watch;
using SysProcess = System.Diagnostics.Process;

namespace Detector.Gui;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly ICaseAnalysisService _caseService;
    private readonly IDisposable? _ownedService;
    private readonly RunPeScanner _runpe = new();
    private readonly GuiDetectionSink _liveSink;
    private readonly FilteringSink _filteredLiveSink;
    private readonly List<DetectionRow> _allFindings = [];
    private CancellationTokenSource? _analysisCts;
    private CancellationTokenSource? _watchCts;
    private AnalysisCase? _currentCase;

    public MainViewModel() : this(new DesktopCaseAnalysisService(), ownsService: true)
    {
        RefreshProcesses();
    }

    public MainViewModel(ICaseAnalysisService caseService) : this(caseService, ownsService: false) { }

    private MainViewModel(ICaseAnalysisService caseService, bool ownsService)
    {
        _caseService = caseService ?? throw new ArgumentNullException(nameof(caseService));
        _ownedService = ownsService ? caseService as IDisposable : null;
        _liveSink = new GuiDetectionSink(AddLiveFinding, SetStatus, AddTrace);
        _filteredLiveSink = new FilteringSink(_liveSink);
        AmsiAvailable = caseService.AmsiAvailable;
        AmsiStatus = caseService.AmsiStatus;
        IsAdmin = CheckAdmin();

        RefreshProcCommand = new RelayCommand(RefreshProcesses, () => !Busy);
        ScanSelectedProcCommand = new RelayCommand(ScanSelectedProcess, () => !Busy && SelectedProcess is not null);
        ScanAllProcCommand = new RelayCommand(ScanAllProcesses, () => !Busy);
        ToggleWatchCommand = new RelayCommand(ToggleWatch);
        ClearLiveCommand = new RelayCommand(() => LiveFindings.Clear(), () => LiveFindings.Count > 0);
        CancelCommand = new RelayCommand(Cancel, () => Busy);
    }

    public ObservableCollection<DetectionRow> Findings { get; } = new();
    public ObservableCollection<CapabilityRow> Capabilities { get; } = new();
    public ObservableCollection<ArtifactRow> Artifacts { get; } = new();
    public ObservableCollection<IndicatorRow> Indicators { get; } = new();
    public ObservableCollection<TimelineRow> Timeline { get; } = new();
    public ObservableCollection<CoverageRow> Coverage { get; } = new();
    public ObservableCollection<DetectionRow> LiveFindings { get; } = new();
    public ObservableCollection<ProcRow> Processes { get; } = new();
    public Array SeverityChoices => Enum.GetValues<Severity>();

    private bool _busy;
    public bool Busy
    {
        get => _busy;
        private set { _busy = value; OnChanged(); OnChanged(nameof(NotBusy)); CommandManager.InvalidateRequerySuggested(); }
    }
    public bool NotBusy => !Busy;
    public bool AmsiAvailable { get; }
    public string AmsiStatus { get; }
    public Brush AmsiBrush => AmsiAvailable ? Rgb(0x17, 0x65, 0x43) : Rgb(0x6E, 0x4A, 0x22);
    public bool IsAdmin { get; }
    public string AdminStatus => IsAdmin ? "Elevated" : "Standard user";
    public Brush AdminBrush => IsAdmin ? Rgb(0x17, 0x65, 0x43) : Rgb(0x33, 0x48, 0x62);

    private string _caseTitle = "No case loaded";
    public string CaseTitle { get => _caseTitle; private set { _caseTitle = value; OnChanged(); } }
    private string _assessmentLabel = "Not assessed";
    public string AssessmentLabel { get => _assessmentLabel; private set { _assessmentLabel = value; OnChanged(); } }
    private string _assessmentSummary = "Choose an artifact, folder, or exported runtime trace to begin.";
    public string AssessmentSummary { get => _assessmentSummary; private set { _assessmentSummary = value; OnChanged(); } }
    private int _artifactCount;
    public int ArtifactCount { get => _artifactCount; private set { _artifactCount = value; OnChanged(); } }
    private int _indicatorCount;
    public int IndicatorCount { get => _indicatorCount; private set { _indicatorCount = value; OnChanged(); } }
    private int _coverageGapCount;
    public int CoverageGapCount { get => _coverageGapCount; private set { _coverageGapCount = value; OnChanged(); } }
    private int _findingCount;
    public int FindingCount { get => _findingCount; private set { _findingCount = value; OnChanged(); } }
    private bool _hasCase;
    public bool HasCase { get => _hasCase; private set { _hasCase = value; OnChanged(); CommandManager.InvalidateRequerySuggested(); } }

    private string _status = "Ready. Static analysis does not execute selected samples.";
    public string Status { get => _status; private set { _status = value; OnChanged(); } }
    private string _filterText = "";
    public string FilterText { get => _filterText; set { _filterText = value ?? ""; OnChanged(); ApplyFindingFilter(); } }
    private Severity _minimumSeverity;
    public Severity MinimumSeverity { get => _minimumSeverity; set { _minimumSeverity = value; OnChanged(); ApplyFindingFilter(); } }
    private DetectionRow? _selectedFinding;
    public DetectionRow? SelectedFinding { get => _selectedFinding; set { _selectedFinding = value; OnChanged(); } }
    private ProcRow? _selectedProcess;
    public ProcRow? SelectedProcess { get => _selectedProcess; set { _selectedProcess = value; OnChanged(); CommandManager.InvalidateRequerySuggested(); } }
    private bool _aggressive;
    public bool Aggressive { get => _aggressive; set { _aggressive = value; OnChanged(); } }
    private bool _filterFps = true;
    public bool FilterFps { get => _filterFps; set { _filterFps = value; OnChanged(); } }
    private bool _advanced;
    public bool Advanced { get => _advanced; set { _advanced = value; OnChanged(); } }
    private bool _isWatching;
    public bool IsWatching { get => _isWatching; private set { _isWatching = value; OnChanged(); OnChanged(nameof(WatchButtonText)); } }
    public string WatchButtonText => IsWatching ? "Stop monitoring" : "Start monitoring";

    public ICommand RefreshProcCommand { get; }
    public ICommand ScanSelectedProcCommand { get; }
    public ICommand ScanAllProcCommand { get; }
    public ICommand ToggleWatchCommand { get; }
    public ICommand ClearLiveCommand { get; }
    public ICommand CancelCommand { get; }

    public Task AnalyzePathAsync(string path) => RunCaseOperationAsync(
        token => _caseService.AnalyzePathAsync(path, token), "Analyzing selected path…", "Analysis complete.");

    public Task ImportRuntimeTraceAsync(string path) => RunCaseOperationAsync(
        token => _caseService.ImportRuntimeTraceAsync(path, token), "Importing runtime evidence…", "Runtime evidence imported.");

    public void ExportCurrentCase(string path, CaseExportFormat format, bool overwrite)
    {
        if (_currentCase is null) throw new InvalidOperationException("No analysis case is loaded.");
        var mode = overwrite ? FileMode.Create : FileMode.CreateNew;
        var content = format == CaseExportFormat.Json
            ? CaseExporter.ToJson(_currentCase)
            : CaseExporter.ToHtml(_currentCase);
        using var stream = new FileStream(path, mode, FileAccess.Write, FileShare.None);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        writer.Write(content);
        Status = $"Exported {format}: {path}";
    }

    public void Cancel() => _analysisCts?.Cancel();

    public async void OnFilesDropped(string[] paths)
    {
        if (paths.Length == 0) return;
        if (paths[0].EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase))
            await ImportRuntimeTraceAsync(paths[0]);
        else
            await AnalyzePathAsync(paths[0]);
    }

    public void Cleanup()
    {
        _analysisCts?.Cancel();
        _watchCts?.Cancel();
        _ownedService?.Dispose();
    }

    private async Task RunCaseOperationAsync(
        Func<CancellationToken, Task<AnalysisCase>> operation, string progress, string completed)
    {
        if (Busy) return;
        _analysisCts = new CancellationTokenSource();
        Busy = true;
        Status = progress;
        try
        {
            var report = await operation(_analysisCts.Token);
            ProjectCase(report);
            Status = completed;
        }
        catch (OperationCanceledException) { Status = "Analysis cancelled."; }
        catch (Exception ex) { Status = $"Analysis failed: {ex.Message}"; }
        finally
        {
            _analysisCts.Dispose();
            _analysisCts = null;
            Busy = false;
        }
    }

    private void ProjectCase(AnalysisCase report)
    {
        _currentCase = report;
        CaseTitle = report.Title;
        AssessmentLabel = report.Assessment.Verdict.ToString();
        AssessmentSummary = report.Assessment.Summary;
        ArtifactCount = report.Artifacts.Count;
        IndicatorCount = report.Indicators.Count;
        CoverageGapCount = report.Coverage.Count(item => item.State != CoverageState.Completed);
        FindingCount = report.Findings.Count;
        HasCase = true;

        _allFindings.Clear();
        _allFindings.AddRange(report.Findings.Select(item => DetectionRow.From(item)));
        ApplyFindingFilter();
        Replace(Capabilities, report.Capabilities.Select(item => new CapabilityRow(
            item.Title, item.Confidence.ToString(), item.Explanation, string.Join(", ", item.SupportingRules))));
        Replace(Artifacts, report.Artifacts.Select(ArtifactRow.From));
        Replace(Indicators, report.Indicators.Select(item => new IndicatorRow(
            item.Kind.ToString(), item.Value, string.Join(", ", item.Sources), string.Join(" · ", item.Contexts))));
        Replace(Timeline, report.Timeline.Select(item => new TimelineRow(
            item.Timestamp?.ToString("u") ?? "—", item.Provider, item.Event,
            item.ProcessId is int pid ? $"{item.ProcessName ?? "unknown"} ({pid})" : item.ProcessName ?? "—",
            string.Join("; ", item.Properties.Select(property => $"{property.Key}={property.Value}")))));
        Replace(Coverage, report.Coverage.Select(item => new CoverageRow(
            item.Module, item.State.ToString(), item.Details, item.State != CoverageState.Completed)));
    }

    private void ApplyFindingFilter()
    {
        var query = _allFindings.Where(item => item.SeverityValue >= MinimumSeverity);
        if (!string.IsNullOrWhiteSpace(FilterText))
            query = query.Where(item => item.SearchText.Contains(FilterText.Trim(), StringComparison.OrdinalIgnoreCase));
        Replace(Findings, query);
    }

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> values)
    {
        target.Clear();
        foreach (var value in values) target.Add(value);
    }

    private IDetectionSink LiveSink => FilterFps ? _filteredLiveSink : _liveSink;

    private void ScanSelectedProcess()
    {
        var process = SelectedProcess;
        if (process is null) return;
        RunLiveAsync(() =>
        {
            foreach (var finding in _runpe.ScanProcess(process.Pid, process.Name, Aggressive))
                LiveSink.Report(finding);
        });
    }

    private void ScanAllProcesses() => RunLiveAsync(() =>
    {
        var findings = _runpe.ScanAll(out var skipped, Aggressive);
        foreach (var finding in findings) LiveSink.Report(finding);
        SetStatus(skipped > 0 ? $"Process scan complete; {skipped} inaccessible." : "Process scan complete.");
    });

    private async void RunLiveAsync(Action action)
    {
        if (Busy) return;
        Busy = true;
        Status = "Running read-only process inspection…";
        try { await Task.Run(action); }
        catch (Exception ex) { Status = $"Process inspection failed: {ex.Message}"; }
        finally { Busy = false; }
    }

    private void ToggleWatch()
    {
        if (IsWatching) { _watchCts?.Cancel(); return; }
        _watchCts = new CancellationTokenSource();
        var token = _watchCts.Token;
        IsWatching = true;
        var desktop = _caseService as DesktopCaseAnalysisService;
        IRealtimeMonitor monitor = EtwSensor.IsElevated()
            ? new EtwSensor(LiveSink, desktop?.Amsi)
            : new WatchService(LiveSink, desktop?.Amsi);
        Status = EtwSensor.IsElevated() ? "Live ETW monitoring active." : "Live polling active; elevate for ETW coverage.";
        Task.Run(() =>
        {
            try { monitor.Run(token); }
            catch (Exception ex) { SetStatus($"Monitoring failed: {ex.Message}"); }
            finally
            {
                (monitor as IDisposable)?.Dispose();
                OnUi(() => IsWatching = false);
            }
        });
    }

    private void RefreshProcesses()
    {
        var rows = new List<ProcRow>();
        foreach (var process in SysProcess.GetProcesses())
        {
            try { rows.Add(new ProcRow { Pid = process.Id, Name = process.ProcessName }); }
            catch { }
            finally { process.Dispose(); }
        }
        Replace(Processes, rows.OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase));
        Status = $"Loaded {Processes.Count} running processes.";
    }

    private void AddLiveFinding(Detection finding) => OnUi(() =>
        LiveFindings.Add(DetectionRow.From(finding, DateTime.Now.ToString("HH:mm:ss"))));

    private void AddTrace(TraceLevel level, string message)
    {
        if (Advanced) OnUi(() => LiveFindings.Add(DetectionRow.Trace(DateTime.Now.ToString("HH:mm:ss"), message)));
    }

    private void SetStatus(string message) => OnUi(() => Status = message);

    private static void OnUi(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess()) action();
        else dispatcher.Invoke(action);
    }

    private static bool CheckAdmin()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
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
    private void OnChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
