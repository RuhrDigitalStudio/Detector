using Detector.Analysis;
using Detector.Model;

namespace Detector.Tests;

public sealed class CorrelationEngineTests
{
    [Fact]
    public void Correlate_RecognizesCompleteProcessInjectionChain()
    {
        var findings = new[]
        {
            Finding("source.cs.open-process"),
            Finding("source.cs.memory-allocation"),
            Finding("source.cs.process-memory-write", Severity.High),
            Finding("source.cs.remote-thread", Severity.High)
        };

        var capability = Assert.Single(CorrelationEngine.Correlate(findings));

        Assert.Equal("capability.process-injection", capability.Id);
        Assert.Equal(Confidence.High, capability.Confidence);
        Assert.Equal(findings.Select(item => item.Rule).Order(), capability.SupportingRules);
    }

    [Fact]
    public void Correlate_DoesNotUpgradeProcessAccessAlone()
    {
        var capabilities = CorrelationEngine.Correlate([Finding("source.cs.open-process")]);

        Assert.DoesNotContain(capabilities, item => item.Id == "capability.process-injection");
    }

    [Fact]
    public void Correlate_TreatsProviderReportedProcessTamperingAsStrongEvidence()
    {
        var capabilities = CorrelationEngine.Correlate(
            [Finding("runtime.process-tampering", Severity.Critical, Verdict.Malicious)]);

        Assert.Contains(capabilities, item =>
            item.Id == "capability.process-injection" && item.Confidence == Confidence.High);
    }

    [Fact]
    public void Correlate_GroupsScriptCapabilitiesWithExplicitConfidence()
    {
        var findings = new[]
        {
            Finding("ps.download-execute", Severity.High),
            Finding("ps.persistence-task", Severity.High),
            Finding("ps.security-exclusion", Severity.High),
            Finding("ps.credential-access", Severity.High)
        };

        var capabilities = CorrelationEngine.Correlate(findings);

        Assert.Contains(capabilities, item => item.Id == "capability.download-execute" && item.Confidence == Confidence.High);
        Assert.Contains(capabilities, item => item.Id == "capability.persistence");
        Assert.Contains(capabilities, item => item.Id == "capability.defense-evasion");
        Assert.Contains(capabilities, item => item.Id == "capability.credential-access");
    }

    [Fact]
    public void Assess_PrioritizesEvidenceAndCallsOutCoverageGaps()
    {
        var findings = new[]
        {
            Finding("rule.error", Severity.Low, Verdict.Error),
            Finding("rule.suspicious", Severity.High, Verdict.Suspicious)
        };
        var coverage = new[]
        {
            new CoverageRecord("AMSI", CoverageState.Unavailable, "No provider."),
            new CoverageRecord("Metadata", CoverageState.Completed, "Read.")
        };

        var assessment = CaseAssessment.Create(findings, coverage, []);

        Assert.Equal(Verdict.Suspicious, assessment.Verdict);
        Assert.Equal(Severity.High, assessment.HighestSeverity);
        Assert.Equal(1, assessment.SuspiciousCount);
        Assert.Equal(1, assessment.ErrorCount);
        Assert.Contains(assessment.CoverageWarnings, item => item.Contains("AMSI", StringComparison.Ordinal));
    }

    [Fact]
    public void Builder_AddsCorrelatedCapabilitiesAndAssessment()
    {
        var builder = new AnalysisCaseBuilder("case-1", "Synthetic", DateTimeOffset.UnixEpoch);
        builder.AddFinding(Finding("ps.download-execute", Severity.High));
        builder.AddCoverage("PowerShell", CoverageState.Completed, "Inspected.");

        var report = builder.Build();

        Assert.Equal(Verdict.Suspicious, report.Assessment.Verdict);
        Assert.Contains(report.Capabilities, item => item.Id == "capability.download-execute");
    }

    [Fact]
    public void HtmlReport_ExplainsAssessmentAndCapabilities()
    {
        var builder = new AnalysisCaseBuilder("case-1", "Synthetic", DateTimeOffset.UnixEpoch);
        builder.AddFinding(Finding("ps.download-execute", Severity.High));

        var html = CaseExporter.ToHtml(builder.Build());

        Assert.Contains("Suspicious evidence reported", html, StringComparison.Ordinal);
        Assert.Contains("Download and execute", html, StringComparison.Ordinal);
    }

    private static Detection Finding(
        string rule,
        Severity severity = Severity.Medium,
        Verdict verdict = Verdict.Suspicious) =>
        new("Synthetic", "sample", severity, verdict, rule, "synthetic evidence");
}
