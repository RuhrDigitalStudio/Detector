using Detector.Analysis;
using Detector.Model;
using Detector.Runtime;

namespace Detector.Tests;

public sealed class RuntimeTraceImporterTests
{
    [Fact]
    public void Import_NormalizesNativeEventsAndExtractsEvidence()
    {
        const string jsonl = """
            {"timestamp":"2026-09-01T10:00:00+02:00","provider":"Lab","event":"ProcessCreate","processId":42,"processName":"powershell","commandLine":"powershell -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABzAHkAbgB0AGgAZQB0AGkAYwA= https://example.invalid/stage"}
            {"timestamp":"2026-09-01T08:00:01Z","provider":"Lab","event":"RegistryValueSet","processId":42,"properties":{"TargetObject":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Demo"}}
            """;

        var result = new RuntimeTraceImporter().Import(new StringReader(jsonl), "trace.jsonl");

        Assert.Equal(2, result.Events.Count);
        Assert.Equal(DateTimeOffset.Parse("2026-09-01T08:00:00Z"), result.Events[0].Timestamp);
        Assert.Contains(result.Findings, item => item.Rule == "runtime.encoded-powershell");
        Assert.Contains(result.Findings, item => item.Rule == "runtime.persistence");
        Assert.Contains(result.Indicators, item => item.Kind == IndicatorKind.Url && item.Value == "https://example.invalid/stage");
        Assert.Contains(result.Indicators, item => item.Kind == IndicatorKind.RegistryPath);
        Assert.Contains(result.Coverage, item => item.State == CoverageState.Completed);
    }

    [Fact]
    public void Import_RecognizesCommonSysmonFields()
    {
        const string jsonl = """
            {"UtcTime":"2026-09-01 08:00:00.000","ProviderName":"Microsoft-Windows-Sysmon","EventID":8,"SourceProcessId":"10","SourceImage":"C:\\Lab\\source.exe","TargetProcessId":"20","TargetImage":"C:\\Lab\\target.exe","StartAddress":"0x1234"}
            """;

        var result = new RuntimeTraceImporter().Import(new StringReader(jsonl), "sysmon.jsonl");

        var timelineEvent = Assert.Single(result.Events);
        Assert.Equal("CreateRemoteThread", timelineEvent.Event);
        Assert.Equal(10, timelineEvent.ProcessId);
        Assert.Equal("source", timelineEvent.ProcessName);
        Assert.Contains(result.Findings, item => item.Rule == "runtime.remote-execution" && item.Severity == Severity.High);
    }

    [Fact]
    public void Import_ReportsMalformedLineAndContinuesWithValidEvidence()
    {
        const string jsonl = """
            {not-json}
            {"timestamp":"2026-09-01T08:00:00Z","provider":"Lab","event":"FileCreate","processId":7}
            """;

        var result = new RuntimeTraceImporter().Import(new StringReader(jsonl), "trace.jsonl");

        Assert.Single(result.Events);
        Assert.Contains(result.Findings, item => item.Rule == "runtime.invalid-line" && item.Details.Contains("line 1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Coverage, item => item.State == CoverageState.Partial);
    }

    [Fact]
    public void Import_HonorsConfiguredTimelineLimit()
    {
        const string jsonl = """
            {"event":"One"}
            {"event":"Two"}
            """;
        var limits = AnalysisLimits.Default with { MaximumTimelineEvents = 1 };

        var result = new RuntimeTraceImporter(limits).Import(new StringReader(jsonl), "trace.jsonl");

        Assert.Single(result.Events);
        Assert.Contains(result.Coverage, item => item.State == CoverageState.Partial && item.Details.Contains("limit", StringComparison.OrdinalIgnoreCase));
    }
}
