using Detector.Model;
using Detector.Reporting;
using Xunit;

public class FilteringSinkTests
{
    private sealed class TestSink : IDetectionSink
    {
        public List<Detection> Reports { get; } = new();
        public List<string> Traces { get; } = new();
        public void Report(Detection d) => Reports.Add(d);
        public void Info(string m) { }
        public void Trace(TraceLevel l, string m) => Traces.Add(m);
    }

    private static Detection Det(string rule, string target = "t") =>
        new("Test", target, Severity.Low, Verdict.Suspicious, rule, "d");

    [Fact]
    public void Duplicates_Are_Collapsed()
    {
        var inner = new TestSink();
        var f = new FilteringSink(inner);
        f.Report(Det("test.rule"));
        f.Report(Det("test.rule")); // identical within window
        Assert.Single(inner.Reports);
        Assert.Equal(1, f.Suppressed);
    }

    [Fact]
    public void Rwx_In_Jit_Host_Is_Suppressed()
    {
        var inner = new TestSink();
        var f = new FilteringSink(inner);
        f.Report(Det("runpe.private-rwx", "chrome (pid 10)") with { ProcessName = "chrome" });
        Assert.Empty(inner.Reports);
        Assert.Contains(inner.Traces, t => t.Contains("jit-host"));
    }

    [Fact]
    public void Rwx_In_Unknown_Process_Passes()
    {
        var inner = new TestSink();
        var f = new FilteringSink(inner);
        f.Report(Det("runpe.private-rwx", "evil (pid 10)") with { ProcessName = "evil" });
        Assert.Single(inner.Reports);
    }

    [Fact]
    public void Critical_Runpe_Pe_Is_Never_Suppressed_In_Jit_Host()
    {
        var inner = new TestSink();
        var f = new FilteringSink(inner);
        // A real PE mapped in private memory is not normal JIT behaviour.
        f.Report(Det("runpe.unbacked-exec-pe", "chrome (pid 10)") with { ProcessName = "chrome" });
        Assert.Single(inner.Reports);
    }

    [Fact]
    public void HighEntropy_On_Trusted_Path_Is_Suppressed()
    {
        var inner = new TestSink();
        var f = new FilteringSink(inner);
        f.Report(Det("heuristic.high-entropy", @"C:\Windows\System32\x.dll")
            with
        { Path = @"C:\Windows\System32\x.dll" });
        Assert.Empty(inner.Reports);
        Assert.Contains(inner.Traces, t => t.Contains("trusted-file"));
    }

    [Fact]
    public void Eicar_On_Trusted_Path_Is_Not_Suppressed()
    {
        var inner = new TestSink();
        var f = new FilteringSink(inner);
        f.Report(Det("heuristic.eicar", @"C:\Windows\System32\x.dll")
            with
        { Path = @"C:\Windows\System32\x.dll" });
        Assert.Single(inner.Reports); // strong rule is never allow-listed
    }

    [Fact]
    public void Disabled_Filter_Passes_Everything()
    {
        var inner = new TestSink();
        var f = new FilteringSink(inner, enabled: false);
        f.Report(Det("runpe.private-rwx") with { ProcessName = "chrome" });
        f.Report(Det("runpe.private-rwx") with { ProcessName = "chrome" });
        Assert.Equal(2, inner.Reports.Count);
    }
}
