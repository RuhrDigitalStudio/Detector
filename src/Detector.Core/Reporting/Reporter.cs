using System.Text.Json;
using Detector.Model;

namespace Detector.Reporting;

/// Renders detections to the console (coloured by severity) and, optionally,
/// appends them as JSON lines to a log file. Tracks the worst verdict so the
/// process can exit with a meaningful code.
public sealed class Reporter : IDetectionSink
{
    private readonly string? _jsonPath;
    private readonly TraceLevel _verbosity;
    private readonly Dictionary<Verdict, int> _counts = new();
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };
    private readonly object _lock = new();

    public Reporter(string? jsonPath, TraceLevel verbosity = TraceLevel.Normal)
    {
        _jsonPath = jsonPath;
        _verbosity = verbosity;
    }

    public void Report(Detection d)
    {
        lock (_lock)
        {
            _counts[d.Verdict] = _counts.GetValueOrDefault(d.Verdict) + 1;

            // Clean results are silent unless the user asked for verbose output.
            if (d.Verdict != Verdict.Clean || _verbosity >= TraceLevel.Verbose)
            {
                var prev = Console.ForegroundColor;
                Console.ForegroundColor = d.Severity switch
                {
                    Severity.Critical or Severity.High => ConsoleColor.Red,
                    Severity.Medium => ConsoleColor.Yellow,
                    Severity.Low => ConsoleColor.Cyan,
                    _ => ConsoleColor.Gray
                };
                Console.WriteLine($"[{d.Verdict,-10}] {d.Source,-10} {d.Rule,-28} {d.Target}");
                Console.ForegroundColor = prev;
                if (!string.IsNullOrEmpty(d.Details))
                    Console.WriteLine($"               -> {d.Details}");
            }

            if (_jsonPath is not null)
            {
                try { File.AppendAllText(_jsonPath, JsonSerializer.Serialize(d, JsonOpts) + Environment.NewLine); }
                catch (Exception ex) { Console.Error.WriteLine($"warn: could not write JSON log: {ex.Message}"); }
            }
        }
    }

    public void Info(string message)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(message);
        Console.ForegroundColor = prev;
    }

    public void Trace(TraceLevel level, string message)
    {
        if (level > _verbosity) return;
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  · {message}");
            Console.ForegroundColor = prev;
        }
    }

    public void Summary()
    {
        lock (_lock)
        {
            Console.WriteLine();
            Console.WriteLine("Summary: "
                + $"clean={_counts.GetValueOrDefault(Verdict.Clean)} "
                + $"suspicious={_counts.GetValueOrDefault(Verdict.Suspicious)} "
                + $"malicious={_counts.GetValueOrDefault(Verdict.Malicious)} "
                + $"error={_counts.GetValueOrDefault(Verdict.Error)}");
        }
    }

    /// Exit code from the worst *finding*. A real detection (malicious/suspicious)
    /// always outranks an incidental scan error, so an unreadable file never
    /// masks a malware hit. 2=malicious, 1=suspicious, 3=error, 0=clean.
    public int ExitCode
    {
        get
        {
            lock (_lock)
            {
                if (_counts.GetValueOrDefault(Verdict.Malicious) > 0) return (int)Verdict.Malicious;
                if (_counts.GetValueOrDefault(Verdict.Suspicious) > 0) return (int)Verdict.Suspicious;
                if (_counts.GetValueOrDefault(Verdict.Error) > 0) return (int)Verdict.Error;
                return (int)Verdict.Clean;
            }
        }
    }

    /// True if any finding was classified malicious (used by selftest to prove
    /// AMSI actually *detected*, not merely errored).
    public bool AnyMalicious
    {
        get { lock (_lock) { return _counts.GetValueOrDefault(Verdict.Malicious) > 0; } }
    }
}
