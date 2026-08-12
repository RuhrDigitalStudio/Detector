using Detector.Watch;
using Xunit;

public class EtwSensorTests
{
    [Theory]
    [InlineData(@"C:\Users\bob\AppData\Local\Temp\evil.dll", true)]
    [InlineData(@"C:\Users\bob\Downloads\payload.dll", true)]
    [InlineData(@"C:\ProgramData\x\hook.dll", true)]
    [InlineData(@"C:\Users\Public\a.dll", true)]
    [InlineData(@"C:\Windows\System32\kernel32.dll", false)]
    [InlineData(@"C:\Program Files\App\app.dll", false)]
    [InlineData(@"C:\Users\bob\AppData\Local\Temp\notes.txt", false)] // not a dll
    [InlineData(null, false)]
    [InlineData("", false)]
    public void IsSuspiciousModulePath_Classifies(string? path, bool expected)
        => Assert.Equal(expected, EtwSensor.IsSuspiciousModulePath(path));
}
