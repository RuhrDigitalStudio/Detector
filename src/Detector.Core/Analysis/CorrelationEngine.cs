using Detector.Model;

namespace Detector.Analysis;

public static class CorrelationEngine
{
    private static readonly string[] ProcessAccess =
    ["source.cs.open-process", "metadata.api.process-access", "runtime.process-access"];
    private static readonly string[] MemoryAllocation =
    ["source.cs.memory-allocation", "metadata.api.memory-allocation", "runtime.memory-allocation"];
    private static readonly string[] MemoryWrite =
    ["source.cs.process-memory-write", "metadata.api.memory-write", "runtime.memory-write"];
    private static readonly string[] RemoteExecution =
    ["source.cs.remote-thread", "metadata.api.remote-execution", "runtime.remote-execution"];
    private static readonly string[] Retrieval =
    ["ps.webclient-download", "ps.remote-fetch", "source.cs.network-client", "metadata.api.network", "runtime.network"];
    private static readonly string[] Execution =
    ["ps.iex", "ps.process-start", "ps.reflection-load", "source.cs.process-start", "source.cs.dynamic-load", "metadata.api.dynamic-loading", "runtime.process-create"];
    private static readonly string[] Persistence =
    ["ps.persistence-task", "ps.persistence-service", "ps.persistence-autorun", "source.cs.registry-autorun", "source.cs.service-control", "metadata.api.persistence", "runtime.persistence"];
    private static readonly string[] DynamicLoading =
    ["ps.reflection-load", "source.cs.dynamic-load", "metadata.api.dynamic-loading"];
    private static readonly string[] DefenseEvasion =
    ["ps.exec-bypass", "ps.window-hidden", "ps.security-exclusion", "ps.security-bypass", "runtime.security-setting"];
    private static readonly string[] CredentialAccess =
    ["ps.credential-access", "metadata.api.credential-access", "runtime.credential-access"];

    public static IReadOnlyList<Capability> Correlate(IEnumerable<Detection> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var material = findings.Where(item => item.Verdict != Verdict.Error).ToArray();
        var rules = material.Select(item => item.Rule).ToHashSet(StringComparer.Ordinal);
        var capabilities = new List<Capability>();

        AddInjection(capabilities, rules);
        AddDownloadExecution(capabilities, rules);
        AddSimple(capabilities, rules, Persistence, "capability.persistence", "Persistence changes",
            "Evidence references a scheduled task, service or autorun mechanism.", Confidence.Medium, highAt: 2);
        AddSimple(capabilities, rules, DynamicLoading, "capability.dynamic-loading", "Dynamic code loading",
            "Evidence references managed reflection or unmanaged library loading.", Confidence.Low, highAt: int.MaxValue);
        AddSimple(capabilities, rules, DefenseEvasion, "capability.defense-evasion", "Defense evasion",
            "Evidence changes security visibility or launches with reduced visibility.", Confidence.Medium, highAt: 2,
            strongRules: ["ps.security-exclusion", "ps.security-bypass", "runtime.security-setting"]);
        AddSimple(capabilities, rules, CredentialAccess, "capability.credential-access", "Credential access",
            "Evidence references credential stores or credential-bearing processes.", Confidence.Medium, highAt: 2);

        return capabilities.OrderByDescending(item => item.Confidence)
            .ThenBy(item => item.Id, StringComparer.Ordinal).ToArray();
    }

    private static void AddInjection(List<Capability> capabilities, ISet<string> rules)
    {
        var direct = rules.Contains("runpe.unbacked-exec-pe") || rules.Contains("runtime.process-tampering");
        var signalGroups = new[] { ProcessAccess, MemoryAllocation, MemoryWrite, RemoteExecution };
        var signalCount = signalGroups.Count(group => group.Any(rules.Contains));
        var primitive = rules.Contains("ps.injection-api");
        if (!direct && signalCount < 2 && !primitive) return;
        var supporting = signalGroups.SelectMany(group => group).Append("runpe.unbacked-exec-pe")
            .Append("runtime.process-tampering").Append("ps.injection-api")
            .Where(rules.Contains).Distinct().Order().ToArray();
        var confidence = direct || signalCount >= 3
            ? Confidence.High
            : signalCount == 2 ? Confidence.Medium : Confidence.Low;
        capabilities.Add(new Capability(
            "capability.process-injection",
            "Process injection",
            confidence,
            direct
                ? "A private executable PE image was observed in process memory."
                : $"Evidence covers {signalCount} of 4 injection stages (process access, allocation, write, execution).",
            supporting));
    }

    private static void AddDownloadExecution(List<Capability> capabilities, ISet<string> rules)
    {
        var direct = rules.Contains("ps.download-execute");
        var hasRetrieval = Retrieval.Any(rules.Contains);
        var hasExecution = Execution.Any(rules.Contains);
        if (!direct && !(hasRetrieval && hasExecution)) return;
        var supporting = Retrieval.Concat(Execution).Append("ps.download-execute")
            .Where(rules.Contains).Distinct().Order().ToArray();
        capabilities.Add(new Capability(
            "capability.download-execute",
            "Download and execute",
            direct ? Confidence.High : Confidence.Medium,
            "Network retrieval and subsequent code or process execution are both represented in the evidence.",
            supporting));
    }

    private static void AddSimple(
        List<Capability> capabilities,
        ISet<string> rules,
        IEnumerable<string> candidates,
        string id,
        string title,
        string explanation,
        Confidence baseConfidence,
        int highAt,
        IEnumerable<string>? strongRules = null)
    {
        var supporting = candidates.Where(rules.Contains).Distinct().Order().ToArray();
        if (supporting.Length == 0) return;
        var strong = strongRules?.Any(rules.Contains) == true;
        var confidence = supporting.Length >= highAt || strong ? Confidence.High : baseConfidence;
        capabilities.Add(new Capability(id, title, confidence, explanation, supporting));
    }
}
