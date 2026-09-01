using Detector.Amsi;
using Detector.Analysis;

namespace Detector.Gui;

public interface ICaseAnalysisService
{
    bool AmsiAvailable { get; }
    string AmsiStatus { get; }
    Task<AnalysisCase> AnalyzePathAsync(string path, CancellationToken cancellationToken);
    Task<AnalysisCase> ImportRuntimeTraceAsync(string path, CancellationToken cancellationToken);
}

/// <summary>Keeps bounded analysis work off the UI thread. Samples are never launched.</summary>
public sealed class DesktopCaseAnalysisService : ICaseAnalysisService, IDisposable
{
    private readonly AmsiScanner? _amsi;
    private readonly AnalysisService _analysis;

    public DesktopCaseAnalysisService()
    {
        try
        {
            _amsi = new AmsiScanner("Detector.Gui");
            AmsiAvailable = true;
            AmsiStatus = "AMSI active";
        }
        catch (Exception ex)
        {
            AmsiStatus = $"AMSI unavailable: {ex.Message}";
        }
        _analysis = new AnalysisService(_amsi, amsiUnavailableReason: AmsiStatus);
    }

    public bool AmsiAvailable { get; }
    public string AmsiStatus { get; } = "AMSI unavailable";
    internal AmsiScanner? Amsi => _amsi;

    public Task<AnalysisCase> AnalyzePathAsync(string path, CancellationToken cancellationToken) =>
        Task.Run(() => _analysis.AnalyzePath(path, cancellationToken: cancellationToken), cancellationToken);

    public Task<AnalysisCase> ImportRuntimeTraceAsync(string path, CancellationToken cancellationToken) =>
        Task.Run(() => _analysis.ImportRuntimeTrace(path, cancellationToken: cancellationToken), cancellationToken);

    public void Dispose() => _amsi?.Dispose();
}
