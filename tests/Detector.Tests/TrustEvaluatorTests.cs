using Detector.Trust;
using Xunit;

public class TrustEvaluatorTests
{
    [Theory]
    [InlineData("dotnet", true)]
    [InlineData("chrome.exe", true)]
    [InlineData("powershell", true)]
    [InlineData("java", true)]
    [InlineData("evil", false)]
    [InlineData("notepad", false)]
    [InlineData(null, false)]
    public void IsKnownJitHost_Classifies(string? name, bool expected)
        => Assert.Equal(expected, TrustEvaluator.IsKnownJitHost(name));

    [Theory]
    [InlineData(@"C:\Windows\System32\kernel32.dll", true)]
    [InlineData(@"C:\Program Files\App\a.dll", true)]
    [InlineData(@"C:\Program Files (x86)\App\a.dll", true)]
    [InlineData(@"C:\Users\bob\AppData\Local\Temp\x.dll", false)]
    [InlineData(@"C:\Users\bob\Downloads\x.dll", false)]
    [InlineData(null, false)]
    public void IsTrustedPath_Classifies(string? path, bool expected)
        => Assert.Equal(expected, TrustEvaluator.IsTrustedPath(path));

    [Fact]
    public void RealSystemDll_IsAuthenticodeTrusted()
    {
        // Integration: a genuine Windows binary must verify as trusted.
        var kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        Assert.True(TrustEvaluator.IsAuthenticodeTrusted(kernel32));
        Assert.True(TrustEvaluator.IsMicrosoftSigned(kernel32));
    }

    [Fact]
    public void UnsignedFile_IsNotTrusted()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"detector_unsigned_{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(tmp, new byte[] { 1, 2, 3, 4, 5 });
        try { Assert.False(TrustEvaluator.IsAuthenticodeTrusted(tmp)); }
        finally { File.Delete(tmp); }
    }
}
