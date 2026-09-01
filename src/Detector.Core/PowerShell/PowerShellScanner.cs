using Detector.Amsi;
using Detector.Analysis;
using Detector.Model;

namespace Detector.PowerShell;

/// Orchestrates PowerShell analysis: deobfuscate into layers, run heuristics on
/// each layer, and (if available) submit each layer to AMSI for a real verdict.
public sealed class PowerShellScanner
{
    private readonly AmsiScanner? _amsi;

    public PowerShellScanner(AmsiScanner? amsi) => _amsi = amsi;

    public IEnumerable<Detection> Scan(string script, string target) =>
        Analyze(script, target).Findings;

    public PowerShellAnalysis Analyze(string script, string target)
    {
        var findings = new List<Detection>();
        var layers = Deobfuscator.Expand(script);
        var indicators = new List<IndicatorCandidate>();
        var indicatorKeys = new HashSet<(IndicatorKind Kind, string Value)>();

        for (int i = 0; i < layers.Count; i++)
        {
            string layer = layers[i];
            string label = i == 0 ? target : $"{target} [layer {i}]";

            foreach (var hit in PsHeuristics.Evaluate(layer))
                findings.Add(new Detection("PowerShell", label, hit.Severity,
                    hit.Severity == Severity.Critical ? Verdict.Malicious : Verdict.Suspicious,
                    hit.Rule, $"matched: {hit.Match}"));

            var remainingIndicators = AnalysisLimits.Default.MaximumIndicators - indicators.Count;
            foreach (var indicator in remainingIndicators > 0
                         ? IndicatorExtractor.Extract(layer, label, remainingIndicators)
                         : [])
            {
                if (indicatorKeys.Add((indicator.Kind, indicator.Value.ToUpperInvariant())))
                    indicators.Add(indicator);
            }

            if (_amsi is not null)
            {
                var d = _amsi.ScanString(layer, label, "script.ps1");
                if (d.Verdict != Verdict.Clean)
                    findings.Add(d with { Source = "AMSI/PS" });
            }
        }

        return new PowerShellAnalysis(layers, findings, indicators);
    }
}

public sealed record PowerShellAnalysis(
    IReadOnlyList<string> Layers,
    IReadOnlyList<Detection> Findings,
    IReadOnlyList<IndicatorCandidate> Indicators);
