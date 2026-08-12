using Detector.Model;
using Detector.Reporting;
using Xunit;

public class ReporterTests
{
    private static Detection Det(Verdict v) =>
        new("Test", "t", Severity.High, v, "test.rule", "d");

    [Fact]
    public void Malicious_Outranks_Error_In_ExitCode()
    {
        var r = new Reporter(null);
        r.Report(Det(Verdict.Malicious));
        r.Report(Det(Verdict.Error));       // an incidental scan error
        Assert.Equal((int)Verdict.Malicious, r.ExitCode);  // must NOT be Error(3)
    }

    [Fact]
    public void Suspicious_Outranks_Error()
    {
        var r = new Reporter(null);
        r.Report(Det(Verdict.Error));
        r.Report(Det(Verdict.Suspicious));
        Assert.Equal((int)Verdict.Suspicious, r.ExitCode);
    }

    [Fact]
    public void Error_Only_Yields_Error_ExitCode()
    {
        var r = new Reporter(null);
        r.Report(Det(Verdict.Error));
        Assert.Equal((int)Verdict.Error, r.ExitCode);
    }

    [Fact]
    public void Clean_Only_Yields_Zero()
    {
        var r = new Reporter(null);
        r.Report(Det(Verdict.Clean));
        Assert.Equal(0, r.ExitCode);
        Assert.False(r.AnyMalicious);
    }

    [Fact]
    public void AnyMalicious_Tracks_Malicious()
    {
        var r = new Reporter(null);
        r.Report(Det(Verdict.Suspicious));
        Assert.False(r.AnyMalicious);
        r.Report(Det(Verdict.Malicious));
        Assert.True(r.AnyMalicious);
    }
}
