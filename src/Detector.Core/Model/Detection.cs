namespace Detector.Model;

/// Severity ranks how alarming a finding is (used for console colour + sorting).
public enum Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

/// Verdict is the classification; its numeric value doubles as the process
/// exit code (0 clean, 1 suspicious, 2 malicious, 3 error).
public enum Verdict { Clean = 0, Suspicious = 1, Malicious = 2, Error = 3 }

/// A single finding produced by any detector. All modules speak this language
/// so the Reporter can render everything uniformly.
public sealed record Detection(
    string Source,     // "AMSI" | "RunPE" | "PowerShell" | "Heuristics" | "Watch"
    string Target,     // file path, "name (pid N)", script path, ...
    Severity Severity,
    Verdict Verdict,
    string Rule,       // stable machine id, e.g. "amsi.detected"
    string Details)    // human-readable explanation
{
    /// Optional file path the finding is about — lets the false-positive filter
    /// check Authenticode trust / trusted locations without parsing Target.
    public string? Path { get; init; }

    /// Optional subject process image name (no extension) — lets the filter
    /// recognise known JIT hosts (RWX there is normal) etc.
    public string? ProcessName { get; init; }
}
