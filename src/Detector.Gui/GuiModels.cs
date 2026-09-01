using System.Windows.Media;
using Detector.Analysis;
using Detector.Model;
using Detector.Reporting;

namespace Detector.Gui;

public enum CaseExportFormat { Json, Html }

public sealed class DetectionRow
{
    public string Time { get; init; } = "";
    public string Source { get; init; } = "";
    public string Verdict { get; init; } = "";
    public string Severity { get; init; } = "";
    public Severity SeverityValue { get; init; }
    public string Rule { get; init; } = "";
    public string Target { get; init; } = "";
    public string Details { get; init; } = "";
    public Brush RowBrush { get; init; } = Brushes.Gainsboro;
    public string SearchText => $"{Source} {Verdict} {Severity} {Rule} {Target} {Details}";

    public static DetectionRow From(Detection detection, string time = "") => new()
    {
        Time = time,
        Source = detection.Source,
        Verdict = detection.Verdict.ToString(),
        Severity = detection.Severity.ToString(),
        SeverityValue = detection.Severity,
        Rule = detection.Rule,
        Target = detection.Target,
        Details = detection.Details,
        RowBrush = SeverityBrush(detection.Severity)
    };

    public static DetectionRow Trace(string time, string message) => new()
    {
        Time = time,
        Source = "trace",
        Severity = "Info",
        Details = message,
        RowBrush = Rgb(0x80, 0x8A, 0x9A)
    };

    private static Brush SeverityBrush(Severity severity) => severity switch
    {
        Detector.Model.Severity.Critical => Rgb(0xFF, 0x6B, 0x7A),
        Detector.Model.Severity.High => Rgb(0xFF, 0x91, 0x6C),
        Detector.Model.Severity.Medium => Rgb(0xF2, 0xC9, 0x4C),
        Detector.Model.Severity.Low => Rgb(0x70, 0xD6, 0xA3),
        _ => Rgb(0xA9, 0xB4, 0xC7)
    };

    private static Brush Rgb(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }
}

public sealed record CapabilityRow(string Title, string Confidence, string Explanation, string Evidence);

public sealed record ArtifactRow(string Name, string Kind, string Size, string Sha256, string Architecture,
    string Framework, string Trust, string Entropy, string Details)
{
    public static ArtifactRow From(ArtifactProfile artifact) => new(
        artifact.DisplayName, artifact.Kind.ToString(), FormatSize(artifact.Size), artifact.Sha256,
        artifact.Architecture ?? "—", artifact.TargetFramework ?? "—", artifact.Trust ?? "Not reported",
        artifact.Entropy.ToString("F2"),
        $"Entry point: {artifact.EntryPoint ?? "—"}\nSubsystem: {artifact.Subsystem ?? "—"}\n" +
        $"Sections: {artifact.Sections.Count}; imports: {artifact.NativeImports.Count}; API references: {artifact.ApiReferences.Count}");

    private static string FormatSize(long size) => size switch
    {
        >= 1_048_576 => $"{size / 1_048_576d:F1} MiB",
        >= 1_024 => $"{size / 1_024d:F1} KiB",
        _ => $"{size} B"
    };
}

public sealed record IndicatorRow(string Kind, string Value, string Sources, string Contexts);
public sealed record TimelineRow(string Time, string Provider, string Event, string Process, string Properties);
public sealed record CoverageRow(string Module, string State, string Details, bool IsGap);

public sealed class ProcRow
{
    private static readonly Brush DefaultBrush = MakeBrush();
    public int Pid { get; init; }
    public string Name { get; init; } = "";
    public Brush RowBrush => DefaultBrush;

    private static Brush MakeBrush()
    {
        var brush = new SolidColorBrush(Color.FromRgb(0xE6, 0xEA, 0xF0));
        brush.Freeze();
        return brush;
    }
}

public sealed class GuiDetectionSink : IDetectionSink
{
    private readonly Action<Detection> _onDetection;
    private readonly Action<string> _onInfo;
    private readonly Action<TraceLevel, string>? _onTrace;

    public GuiDetectionSink(Action<Detection> onDetection, Action<string> onInfo,
        Action<TraceLevel, string>? onTrace = null)
    {
        _onDetection = onDetection;
        _onInfo = onInfo;
        _onTrace = onTrace;
    }

    public void Report(Detection detection) => _onDetection(detection);
    public void Info(string message) => _onInfo(message);
    public void Trace(TraceLevel level, string message) => _onTrace?.Invoke(level, message);
}
