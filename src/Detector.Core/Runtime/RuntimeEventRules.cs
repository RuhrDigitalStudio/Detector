using Detector.Analysis;
using Detector.Model;
using Detector.PowerShell;

namespace Detector.Runtime;

public static class RuntimeEventRules
{
    public static IReadOnlyList<Detection> Evaluate(TimelineEvent timelineEvent, string source)
    {
        ArgumentNullException.ThrowIfNull(timelineEvent);
        var findings = new List<Detection>();
        var target = timelineEvent.ProcessId is int pid
            ? $"{timelineEvent.ProcessName ?? timelineEvent.Event} (pid {pid})"
            : timelineEvent.ProcessName ?? timelineEvent.Event;
        var values = string.Join(' ', timelineEvent.Properties.Values);

        if (timelineEvent.Event.Equals("CreateRemoteThread", StringComparison.OrdinalIgnoreCase))
            findings.Add(Finding(target, Severity.High, "runtime.remote-execution",
                "A runtime trace recorded remote-thread creation.", source));

        if (timelineEvent.Event.Equals("ProcessAccess", StringComparison.OrdinalIgnoreCase) &&
            IsProcessModificationAccess(timelineEvent.Properties))
            findings.Add(Finding(target, Severity.Medium, "runtime.process-access",
                "Process access includes memory modification or thread creation rights.", source));

        if (timelineEvent.Event.Equals("ProcessTampering", StringComparison.OrdinalIgnoreCase))
            findings.Add(new Detection(source, target, Severity.Critical, Verdict.Malicious,
                "runtime.process-tampering", "The trace provider reported process-image tampering."));

        if (timelineEvent.Event.Contains("Registry", StringComparison.OrdinalIgnoreCase) &&
            (values.Contains("CurrentVersion\\Run", StringComparison.OrdinalIgnoreCase) ||
             values.Contains("CurrentVersion\\RunOnce", StringComparison.OrdinalIgnoreCase) ||
             values.Contains("System\\CurrentControlSet\\Services", StringComparison.OrdinalIgnoreCase)))
            findings.Add(Finding(target, Severity.High, "runtime.persistence",
                "A runtime registry event targets an autorun or service location.", source));

        var commandLine = Property(timelineEvent.Properties, "commandLine", "CommandLine");
        if (!string.IsNullOrEmpty(commandLine))
        {
            var scriptHits = PsHeuristics.Evaluate(commandLine);
            if (scriptHits.Any(item => item.Rule == "ps.encodedcommand"))
            {
                findings.Add(Finding(target, Severity.High, "runtime.encoded-powershell",
                    "A process command line contains an encoded PowerShell command.", source));
                findings.Add(Finding(target, Severity.Medium, "runtime.process-create",
                    "A suspicious script process was created.", source));
            }
            if (SuspiciousParentChild(timelineEvent.Properties))
                findings.Add(Finding(target, Severity.High, "runtime.suspicious-child",
                    "An Office application launched a script or living-off-the-land process.", source));
        }
        return findings;
    }

    private static Detection Finding(string target, Severity severity, string rule, string details, string source) =>
        new(source, target, severity, Verdict.Suspicious, rule, details);

    private static bool IsProcessModificationAccess(IReadOnlyDictionary<string, string> properties)
    {
        var value = Property(properties, "GrantedAccess", "grantedAccess");
        if (string.IsNullOrWhiteSpace(value)) return false;
        value = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;
        return int.TryParse(value, System.Globalization.NumberStyles.HexNumber,
                   System.Globalization.CultureInfo.InvariantCulture, out var access) &&
               (access & (0x0002 | 0x0008 | 0x0020)) != 0;
    }

    private static bool SuspiciousParentChild(IReadOnlyDictionary<string, string> properties)
    {
        var parent = Property(properties, "ParentImage", "parentImage") ?? string.Empty;
        var image = Property(properties, "Image", "image", "SourceImage") ?? string.Empty;
        var office = ContainsAny(parent, "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe");
        var child = ContainsAny(image, "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe");
        return office && child;
    }

    private static string? Property(IReadOnlyDictionary<string, string> properties, params string[] names)
    {
        foreach (var name in names)
            if (properties.TryGetValue(name, out var value)) return value;
        return null;
    }

    private static bool ContainsAny(string value, params string[] candidates) =>
        candidates.Any(item => value.Contains(item, StringComparison.OrdinalIgnoreCase));
}
