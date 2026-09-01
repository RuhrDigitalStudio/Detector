using Detector.Analysis;
using Detector.Gui;
using Detector.Model;

namespace Detector.Tests;

public sealed class MainViewModelTests
{
    [Fact]
    public async Task AnalyzePathAsync_ProjectsCompleteCaseIntoWorkspace()
    {
        var report = BuildCase();
        var service = new FakeCaseAnalysisService(report);
        var viewModel = new MainViewModel(service);

        await viewModel.AnalyzePathAsync("sample.dll");

        Assert.Equal("Synthetic case", viewModel.CaseTitle);
        Assert.Equal("Suspicious", viewModel.AssessmentLabel);
        Assert.Equal(1, viewModel.ArtifactCount);
        Assert.Equal(1, viewModel.IndicatorCount);
        Assert.Equal(1, viewModel.CoverageGapCount);
        Assert.Single(viewModel.Findings);
        Assert.Single(viewModel.Capabilities);
        Assert.Single(viewModel.Artifacts);
        Assert.Single(viewModel.Indicators);
        Assert.False(viewModel.Busy);
        Assert.Equal("sample.dll", service.LastAnalyzedPath);
    }

    [Fact]
    public async Task FindingFilters_KeepStrongRelevantRows()
    {
        var builder = NewBuilder();
        builder.AddFinding(Finding("low.rule", Severity.Low, "low detail"));
        builder.AddFinding(Finding("high.rule", Severity.High, "network retrieval"));
        var viewModel = new MainViewModel(new FakeCaseAnalysisService(builder.Build()));
        await viewModel.AnalyzePathAsync("sample");

        viewModel.MinimumSeverity = Severity.High;
        viewModel.FilterText = "network";

        var row = Assert.Single(viewModel.Findings);
        Assert.Equal("high.rule", row.Rule);
    }

    [Fact]
    public async Task ImportRuntimeTraceAsync_UsesTraceServicePath()
    {
        var service = new FakeCaseAnalysisService(BuildCase());
        var viewModel = new MainViewModel(service);

        await viewModel.ImportRuntimeTraceAsync("trace.jsonl");

        Assert.Equal("trace.jsonl", service.LastTracePath);
        Assert.True(viewModel.HasCase);
    }

    [Fact]
    public async Task ExportCurrentCase_WritesSelectedFormat()
    {
        var root = CreateDirectory();
        try
        {
            var viewModel = new MainViewModel(new FakeCaseAnalysisService(BuildCase()));
            await viewModel.AnalyzePathAsync("sample");
            var jsonPath = Path.Combine(root, "case.json");
            var htmlPath = Path.Combine(root, "case.html");

            viewModel.ExportCurrentCase(jsonPath, CaseExportFormat.Json, overwrite: false);
            viewModel.ExportCurrentCase(htmlPath, CaseExportFormat.Html, overwrite: false);

            Assert.Equal("Synthetic case", CaseExporter.FromJson(File.ReadAllText(jsonPath)).Title);
            Assert.Contains("Synthetic case", File.ReadAllText(htmlPath), StringComparison.Ordinal);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task AnalyzePathAsync_ReportsServiceFailureWithoutLeavingBusyState()
    {
        var service = new FakeCaseAnalysisService(new IOException("read failed"));
        var viewModel = new MainViewModel(service);

        await viewModel.AnalyzePathAsync("sample");

        Assert.False(viewModel.Busy);
        Assert.Contains("read failed", viewModel.Status, StringComparison.OrdinalIgnoreCase);
        Assert.False(viewModel.HasCase);
    }

    private static AnalysisCase BuildCase()
    {
        var builder = NewBuilder();
        builder.AddArtifact(new ArtifactProfile("id", "sample.dll", 42, new string('A', 64), ArtifactKind.ManagedAssembly));
        builder.AddFinding(Finding("ps.download-execute", Severity.High, "network retrieval and execution"));
        builder.AddIndicator(IndicatorKind.Domain, "example.invalid", "PowerShell", "decoded layer");
        builder.AddCoverage("Metadata", CoverageState.Completed, "Read.");
        builder.AddCoverage("AMSI", CoverageState.Unavailable, "No provider.");
        return builder.Build();
    }

    private static AnalysisCaseBuilder NewBuilder() =>
        new("case-1", "Synthetic case", DateTimeOffset.UnixEpoch);

    private static Detection Finding(string rule, Severity severity, string details) =>
        new("Synthetic", "sample", severity, Verdict.Suspicious, rule, details);

    private static string CreateDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "DetectorTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed class FakeCaseAnalysisService : ICaseAnalysisService
    {
        private readonly AnalysisCase? _report;
        private readonly Exception? _error;

        public FakeCaseAnalysisService(AnalysisCase report) => _report = report;

        public FakeCaseAnalysisService(Exception error) => _error = error;

        public bool AmsiAvailable => false;

        public string AmsiStatus => "AMSI unavailable";

        public string? LastAnalyzedPath { get; private set; }

        public string? LastTracePath { get; private set; }

        public Task<AnalysisCase> AnalyzePathAsync(string path, CancellationToken cancellationToken)
        {
            LastAnalyzedPath = path;
            return Result();
        }

        public Task<AnalysisCase> ImportRuntimeTraceAsync(string path, CancellationToken cancellationToken)
        {
            LastTracePath = path;
            return Result();
        }

        private Task<AnalysisCase> Result() => _error is null
            ? Task.FromResult(_report!)
            : Task.FromException<AnalysisCase>(_error);
    }
}
