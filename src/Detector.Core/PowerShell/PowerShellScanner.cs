using Detector.Amsi;
using Detector.Model;

namespace Detector.PowerShell;

/// Orchestrates PowerShell analysis: deobfuscate into layers, run heuristics on
/// each layer, and (if available) submit each layer to AMSI for a real verdict.
public sealed class PowerShellScanner
{
    private readonly AmsiScanner? _amsi;

    public PowerShellScanner(AmsiScanner? amsi) => _amsi = amsi;

    public IEnumerable<Detection> Scan(string script, string target)
    {
        var findings = new List<Detection>();
        var layers = Deobfuscator.Expand(script);

        for (int i = 0; i < layers.Count; i++)
        {
            string layer = layers[i];
            string label = i == 0 ? target : $"{target} [layer {i}]";

            foreach (var hit in PsHeuristics.Evaluate(layer))
                findings.Add(new Detection("PowerShell", label, hit.Severity,
                    hit.Severity == Severity.Critical ? Verdict.Malicious : Verdict.Suspicious,
                    hit.Rule, $"matched: {hit.Match}"));

            if (_amsi is not null)
            {
                var d = _amsi.ScanString(layer, label, "script.ps1");
                if (d.Verdict != Verdict.Clean)
                    findings.Add(d with { Source = "AMSI/PS" });
            }
        }

        return findings;
    }
}
