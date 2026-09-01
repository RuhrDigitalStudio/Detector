using Detector.Analysis;
using Detector.Cli;
using Detector.Model;

namespace Detector.Tests;

public sealed class CaseCommandRunnerTests
{
    [Fact]
    public void Analyze_WritesJsonAndHtmlReports()
    {
        var root = CreateDirectory();
        try
        {
            var input = Path.Combine(root, "sample.cs");
            var jsonPath = Path.Combine(root, "case.json");
            var htmlPath = Path.Combine(root, "case.html");
            File.WriteAllText(input, "class X { void Go() { Assembly.Load(new byte[0]); } }");
            var options = CliOptions.Parse(
                ["analyze", input, "--report-json", jsonPath, "--report-html", htmlPath, "--no-amsi"]);
            var output = new StringWriter();

            var exitCode = CaseCommandRunner.Analyze(options, null, output, TextWriter.Null);

            Assert.Equal(1, exitCode);
            Assert.True(File.Exists(jsonPath));
            Assert.True(File.Exists(htmlPath));
            Assert.Equal(Verdict.Suspicious, CaseExporter.FromJson(File.ReadAllText(jsonPath)).Assessment.Verdict);
            Assert.Contains("Dynamic code loading", File.ReadAllText(htmlPath), StringComparison.Ordinal);
            Assert.Contains("Suspicious", output.ToString(), StringComparison.Ordinal);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void Analyze_PrintsJsonWhenNoReportPathIsSelected()
    {
        var root = CreateDirectory();
        try
        {
            var input = Path.Combine(root, "note.txt");
            File.WriteAllText(input, "synthetic note");
            var options = CliOptions.Parse(["analyze", input, "--no-amsi"]);
            var output = new StringWriter();

            var exitCode = CaseCommandRunner.Analyze(options, null, output, TextWriter.Null);
            var report = CaseExporter.FromJson(output.ToString());

            Assert.Equal(0, exitCode);
            Assert.Single(report.Artifacts);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void ImportTrace_WritesTimelineCase()
    {
        var root = CreateDirectory();
        try
        {
            var input = Path.Combine(root, "trace.jsonl");
            File.WriteAllText(input, "{\"event\":\"CreateRemoteThread\",\"processId\":4}");
            var options = CliOptions.Parse(["import-trace", input]);
            var output = new StringWriter();

            var exitCode = CaseCommandRunner.ImportTrace(options, output, TextWriter.Null);
            var report = CaseExporter.FromJson(output.ToString());

            Assert.Equal(1, exitCode);
            Assert.Single(report.Timeline);
            Assert.Contains(report.Findings, item => item.Rule == "runtime.remote-execution");
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static string CreateDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "DetectorTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
