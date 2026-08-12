using Detector.Cli;
using Xunit;

public class CliOptionsTests
{
    [Fact]
    public void Json_With_Valid_Path_Parses()
    {
        var o = CliOptions.Parse(new[] { "scan-file", "x.exe", "--json", "log.jsonl" });
        Assert.Equal("scan-file", o.Command);
        Assert.Equal("log.jsonl", o.JsonPath);
        Assert.Null(o.Error);
    }

    [Fact]
    public void Json_Without_Operand_Errors()
    {
        var o = CliOptions.Parse(new[] { "scan-file", "x.exe", "--json" });
        Assert.NotNull(o.Error);
        Assert.Null(o.JsonPath);
    }

    [Fact]
    public void Json_Does_Not_Swallow_Following_Flag()
    {
        var o = CliOptions.Parse(new[] { "scan-file", "x.exe", "--json", "--verbose" });
        Assert.NotNull(o.Error);         // --verbose is not a path
        Assert.Null(o.JsonPath);
    }

    [Fact]
    public void Flags_And_Positionals_Parse()
    {
        var o = CliOptions.Parse(new[] { "scan-proc", "1234", "--aggressive", "--no-amsi", "-v" });
        Assert.Equal("scan-proc", o.Command);
        Assert.Equal("1234", Assert.Single(o.Positional));
        Assert.True(o.Aggressive);
        Assert.True(o.NoAmsi);
        Assert.True(o.Verbose);
    }
}
