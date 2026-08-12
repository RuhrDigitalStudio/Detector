using System.Text;
using Detector.PowerShell;
using Xunit;

public class DeobfuscatorTests
{
    [Fact]
    public void Decodes_EncodedCommand_Utf16Base64()
    {
        var payload = "Write-Host hacked";
        var b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(payload));
        var input = $"powershell.exe -nop -w hidden -enc {b64}";
        var layers = Deobfuscator.Expand(input);
        Assert.Contains(layers, l => l.Contains("Write-Host hacked"));
    }

    [Fact]
    public void Decodes_Standalone_Base64_Ascii_Blob()
    {
        var b64 = Convert.ToBase64String(Encoding.ASCII.GetBytes("IEX(New-Object Net.WebClient)"));
        var layers = Deobfuscator.Expand($"$x = '{b64}'");
        Assert.Contains(layers, l => l.Contains("Net.WebClient"));
    }

    [Fact]
    public void Returns_Original_When_Nothing_To_Decode()
    {
        var layers = Deobfuscator.Expand("Get-Process");
        Assert.Single(layers);
        Assert.Equal("Get-Process", layers[0]);
    }

    [Fact]
    public void Includes_Original_As_First_Layer()
    {
        var layers = Deobfuscator.Expand("whatever -enc AAAA");
        Assert.Equal("whatever -enc AAAA", layers[0]);
    }

    [Theory]
    [InlineData("-e")]
    [InlineData("-en")]
    [InlineData("-enc")]
    [InlineData("-enco")]
    [InlineData("-encod")]
    [InlineData("-encodedcommand")]
    public void Decodes_All_EncodedCommand_Abbreviations(string flag)
    {
        var b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Host pwned"));
        var layers = Deobfuscator.Expand($"powershell {flag} {b64}");
        Assert.Contains(layers, l => l.Contains("Write-Host pwned"));
    }
}
