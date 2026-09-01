using Detector.Cli;

namespace Detector.Tests;

[CollectionDefinition("Console", DisableParallelization = true)]
public sealed class ConsoleCollection;

[Collection("Console")]
public sealed class CliHelpTests
{
    [Fact]
    public void Help_DescribesCaseAnalysisBoundary()
    {
        var original = Console.Out;
        using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            var exitCode = CommandRouter.Run(["help"]);

            Assert.Equal(0, exitCode);
            Assert.Contains("defensive Windows analysis workbench", output.ToString(), StringComparison.Ordinal);
            Assert.Contains("do not launch selected samples", output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("antivirus", output.ToString(), StringComparison.OrdinalIgnoreCase);
        }
        finally { Console.SetOut(original); }
    }
}
