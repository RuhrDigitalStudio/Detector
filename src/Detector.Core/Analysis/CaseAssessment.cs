using Detector.Model;

namespace Detector.Analysis;

public sealed record CaseAssessment(
    Verdict Verdict,
    Severity HighestSeverity,
    int CleanCount,
    int SuspiciousCount,
    int MaliciousCount,
    int ErrorCount,
    string Summary,
    IReadOnlyList<string> CoverageWarnings)
{
    public static CaseAssessment Create(
        IEnumerable<Detection> findings,
        IEnumerable<CoverageRecord> coverage,
        IEnumerable<Capability> capabilities)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(coverage);
        ArgumentNullException.ThrowIfNull(capabilities);
        var findingList = findings.ToArray();
        var capabilityList = capabilities.ToArray();
        var malicious = findingList.Count(item => item.Verdict == Verdict.Malicious);
        var suspicious = findingList.Count(item => item.Verdict == Verdict.Suspicious);
        var errors = findingList.Count(item => item.Verdict == Verdict.Error);
        var clean = findingList.Count(item => item.Verdict == Verdict.Clean);
        var verdict = malicious > 0
            ? Verdict.Malicious
            : suspicious > 0 ? Verdict.Suspicious : errors > 0 ? Verdict.Error : Verdict.Clean;
        var highest = findingList.Length == 0 ? Severity.Info : findingList.Max(item => item.Severity);
        var warnings = coverage.Where(item => item.State != CoverageState.Completed)
            .Select(item => $"{item.Module}: {item.Details}")
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal).ToArray();
        var summary = verdict switch
        {
            Verdict.Malicious => $"Malicious evidence reported; {capabilityList.Length} capability group(s) correlated.",
            Verdict.Suspicious => $"Suspicious evidence reported; {capabilityList.Length} capability group(s) correlated.",
            Verdict.Error => "Analysis errors prevented a clean assessment.",
            _ when warnings.Length > 0 => "No suspicious finding was reported, but coverage is incomplete.",
            _ => "No suspicious finding was reported by the completed modules."
        };
        return new CaseAssessment(verdict, highest, clean, suspicious, malicious, errors, summary, warnings);
    }
}
