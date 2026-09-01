using Detector.Analysis;
using Detector.Model;

namespace Detector.Tests;

public sealed class AnalysisCaseTests
{
    private static readonly DateTimeOffset CreatedAt =
        new(2026, 9, 1, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Build_MergesEquivalentIndicatorsAndPreservesEvidenceSources()
    {
        var builder = NewBuilder();
        builder.AddIndicator(IndicatorKind.Url, "HTTPS://Example.invalid/payload", "PowerShell", "download");
        builder.AddIndicator(IndicatorKind.Url, "https://example.invalid/payload", "Runtime", "connection");

        var report = builder.Build();

        var indicator = Assert.Single(report.Indicators);
        Assert.Equal("https://example.invalid/payload", indicator.Value);
        Assert.Equal(["PowerShell", "Runtime"], indicator.Sources);
        Assert.Equal(["connection", "download"], indicator.Contexts);
    }

    [Fact]
    public void Build_OrdersFindingsAndIndicatorsDeterministically()
    {
        var builder = NewBuilder();
        builder.AddFinding(new Detection("SourceB", "z", Severity.Low, Verdict.Suspicious, "rule.z", "z"));
        builder.AddFinding(new Detection("SourceA", "a", Severity.High, Verdict.Suspicious, "rule.a", "a"));
        builder.AddIndicator(IndicatorKind.Domain, "z.invalid", "SourceB", "z");
        builder.AddIndicator(IndicatorKind.Domain, "a.invalid", "SourceA", "a");

        var report = builder.Build();

        Assert.Equal(["rule.a", "rule.z"], report.Findings.Select(item => item.Rule));
        Assert.Equal(["a.invalid", "z.invalid"], report.Indicators.Select(item => item.Value));
    }

    [Fact]
    public void Build_KeepsCoverageFailuresVisible()
    {
        var builder = NewBuilder();
        builder.AddCoverage("AMSI", CoverageState.Unavailable, "No provider registered.");
        builder.AddCoverage("Fingerprint", CoverageState.Completed, "SHA-256 calculated.");

        var report = builder.Build();

        Assert.True(report.HasCoverageGaps);
        Assert.Equal(CoverageState.Unavailable, report.Coverage.Single(item => item.Module == "AMSI").State);
    }

    [Fact]
    public void Json_RoundTripsTheStableCaseSchema()
    {
        var builder = NewBuilder();
        builder.AddArtifact(new ArtifactProfile("artifact-1", "sample.dll", 42, "AABB", ArtifactKind.ManagedAssembly));
        builder.AddFinding(new Detection("Metadata", "sample.dll", Severity.Medium, Verdict.Suspicious, "dotnet.dynamic-load", "Reflection load reference."));
        builder.AddIndicator(IndicatorKind.Domain, "example.invalid", "Strings", "metadata");
        builder.AddCoverage("Metadata", CoverageState.Completed, "Metadata read without loading the assembly.");
        var original = builder.Build();

        var json = CaseExporter.ToJson(original);
        var restored = CaseExporter.FromJson(json);

        Assert.Equal(AnalysisCase.CurrentSchemaVersion, restored.SchemaVersion);
        Assert.Equal(original.CaseId, restored.CaseId);
        Assert.Equal(original.Artifacts, restored.Artifacts);
        Assert.Equal(original.Findings, restored.Findings);
        Assert.Equal(original.Indicators, restored.Indicators);
        Assert.Equal(original.Coverage, restored.Coverage);
    }

    [Fact]
    public void Html_EncodesUntrustedArtifactAndFindingText()
    {
        var builder = NewBuilder("<script>alert('case')</script>");
        builder.AddArtifact(new ArtifactProfile("artifact-1", "<img src=x onerror=alert(1)>.dll", 1, "AA", ArtifactKind.ManagedAssembly));
        builder.AddFinding(new Detection("Test", "target", Severity.High, Verdict.Suspicious, "rule.test", "<b>not markup</b>"));

        var html = CaseExporter.ToHtml(builder.Build());

        Assert.DoesNotContain("<script>alert", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img src=x", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<b>not markup", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.Contains("&lt;b&gt;not markup&lt;/b&gt;", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Builder_RejectsCollectionsBeyondConfiguredLimits()
    {
        var limits = AnalysisLimits.Default with { MaximumFindings = 1 };
        var builder = new AnalysisCaseBuilder("case-1", "Bounded", CreatedAt, limits);
        builder.AddFinding(new Detection("Test", "one", Severity.Low, Verdict.Suspicious, "rule.one", "one"));

        var error = Assert.Throws<AnalysisLimitException>(() =>
            builder.AddFinding(new Detection("Test", "two", Severity.Low, Verdict.Suspicious, "rule.two", "two")));

        Assert.Contains("findings", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Json_RejectsNullCollectionsAsInvalidInput()
    {
        const string json = """
            {
              "schemaVersion": 1,
              "caseId": "case-1",
              "title": "Invalid",
              "createdAt": "2026-09-01T10:00:00+00:00",
              "artifacts": null,
              "findings": [],
              "indicators": [],
              "capabilities": [],
              "timeline": [],
              "coverage": []
            }
            """;

        Assert.Throws<InvalidDataException>(() => CaseExporter.FromJson(json));
    }

    [Fact]
    public void Builder_RejectsOversizedTimelinePropertyMaps()
    {
        var limits = AnalysisLimits.Default with { MaximumTimelineProperties = 1 };
        var builder = new AnalysisCaseBuilder("case-1", "Bounded", CreatedAt, limits);
        var properties = new Dictionary<string, string>
        {
            ["Image"] = "sample.exe",
            ["CommandLine"] = "sample.exe --test"
        };

        Assert.Throws<AnalysisLimitException>(() => builder.AddTimelineEvent(
            new TimelineEvent(CreatedAt, "Synthetic", "ProcessCreate", 42, "sample", properties)));
    }

    private static AnalysisCaseBuilder NewBuilder(string title = "Synthetic case") =>
        new("case-1", title, CreatedAt);
}
