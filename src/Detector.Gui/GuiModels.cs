using System.Windows.Media;
using Detector.Model;
using Detector.Reporting;

namespace Detector.Gui;

/// A row in the results grid (Detection + capture time + a severity colour).
public sealed class DetectionRow
{
    public string Time { get; init; } = "";
    public string Source { get; init; } = "";
    public string Verdict { get; init; } = "";
    public string Severity { get; init; } = "";
    public string Rule { get; init; } = "";
    public string Target { get; init; } = "";
    public string Details { get; init; } = "";
    public Brush RowBrush { get; init; } = Brushes.Gainsboro;

    public static DetectionRow From(Detection d, string time)
    {
        Brush brush = d.Severity switch
        {
            Detector.Model.Severity.Critical => Rgb(0xFF, 0x6B, 0x6B),
            Detector.Model.Severity.High => Rgb(0xFF, 0x8A, 0x8A),
            Detector.Model.Severity.Medium => Rgb(0xF2, 0xC9, 0x4C),
            Detector.Model.Severity.Low => Rgb(0x6F, 0xCF, 0x97),
            _ => Rgb(0xB8, 0xBE, 0xC4),
        };
        return new DetectionRow
        {
            Time = time,
            Source = d.Source,
            Verdict = d.Verdict.ToString(),
            Severity = d.Severity.ToString(),
            Rule = d.Rule,
            Target = d.Target,
            Details = d.Details,
            RowBrush = brush,
        };
    }

    /// A dim, non-finding row for the advanced trace stream (raw events, filtered
    /// items). Shown only when the user enables the advanced view.
    public static DetectionRow Trace(string time, string message) => new()
    {
        Time = time,
        Source = "trace",
        Verdict = "",
        Severity = "Info",
        Rule = "",
        Target = "",
        Details = message,
        RowBrush = Rgb(0x80, 0x86, 0x8C),
    };

    private static Brush Rgb(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }
}

/// A running process shown in the Processes tab.
public sealed class ProcRow
{
    private static readonly Brush DefaultBrush = Make();
    public int Pid { get; init; }
    public string Name { get; init; } = "";
    // The shared DataGrid cell style binds Foreground to RowBrush; give process
    // rows a neutral light colour so their text is visible on the dark theme.
    public Brush RowBrush => DefaultBrush;

    private static Brush Make()
    {
        var b = new SolidColorBrush(Color.FromRgb(0xE6, 0xE6, 0xE6));
        b.Freeze();
        return b;
    }
}

/// Bridges Core scanners/watch to the GUI: forwards findings and status text to
/// the caller-supplied delegates (which marshal onto the UI thread).
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
