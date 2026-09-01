using Detector.Model;

namespace Detector.Analysis;

public static class SourceAnalyzer
{
    private static readonly SourceRule[] Rules =
    [
        new("source.cs.pinvoke", Severity.Low, ["DllImport(", "LibraryImport("]),
        new("source.cs.open-process", Severity.Medium, ["OpenProcess(", "NtOpenProcess("]),
        new("source.cs.memory-allocation", Severity.Medium, ["VirtualAllocEx(", "NtAllocateVirtualMemory("]),
        new("source.cs.process-memory-write", Severity.High, ["WriteProcessMemory(", "NtWriteVirtualMemory("]),
        new("source.cs.remote-thread", Severity.High, ["CreateRemoteThread(", "NtCreateThreadEx(", "QueueUserAPC("]),
        new("source.cs.process-start", Severity.Low, ["Process.Start(", "ProcessStartInfo("]),
        new("source.cs.network-client", Severity.Low, ["HttpClient(", "WebClient(", "DownloadString(", "DownloadData("]),
        new("source.cs.dynamic-load", Severity.Medium, ["Assembly.Load(", "Assembly.LoadFrom(", "NativeLibrary.Load(", "LoadLibrary("]),
        new("source.cs.registry-autorun", Severity.Medium, ["CurrentVersion\\Run", "CurrentVersion\\RunOnce"]),
        new("source.cs.service-control", Severity.Medium, ["CreateService(", "ServiceController("])
    ];

    public static IReadOnlyList<Detection> AnalyzeCSharp(string source, string target)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        var lines = source.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var findings = new List<Detection>();
        foreach (var rule in Rules)
        {
            for (var index = 0; index < lines.Length; index++)
            {
                if (!rule.Tokens.Any(token => lines[index].Contains(token, StringComparison.OrdinalIgnoreCase)))
                    continue;
                var evidence = lines[index].Trim();
                if (evidence.Length > 180) evidence = string.Concat(evidence.AsSpan(0, 177), "...");
                findings.Add(new Detection(
                    "C# source",
                    target,
                    rule.Severity,
                    Verdict.Suspicious,
                    rule.Id,
                    $"Matched on line {index + 1}: {evidence}")
                { Path = target });
                break;
            }
        }
        return findings;
    }

    private sealed record SourceRule(string Id, Severity Severity, string[] Tokens);
}
