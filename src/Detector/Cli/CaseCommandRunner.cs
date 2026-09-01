using System.Text;
using System.Text.Json;
using Detector.Amsi;
using Detector.Analysis;

namespace Detector.Cli;

public static class CaseCommandRunner
{
    private static readonly UTF8Encoding Utf8NoBom = new(false);

    public static int Analyze(
        CliOptions options,
        AmsiScanner? amsi,
        TextWriter output,
        TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Positional.Count != 1)
        {
            error.WriteLine("usage: detector analyze <path> [--report-json path] [--report-html path]");
            return 3;
        }
        try
        {
            var reason = options.NoAmsi
                ? "AMSI was disabled for this analysis."
                : "No AMSI provider was available for this analysis.";
            var report = new AnalysisService(amsi, amsiUnavailableReason: reason)
                .AnalyzePath(options.Positional[0]);
            WriteReports(options, report, output);
            return (int)report.Assessment.Verdict;
        }
        catch (Exception ex) when (Expected(ex))
        {
            error.WriteLine($"error: {ex.Message}");
            return 3;
        }
    }

    public static int ImportTrace(CliOptions options, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Positional.Count != 1)
        {
            error.WriteLine("usage: detector import-trace <path> [--report-json path] [--report-html path]");
            return 3;
        }
        try
        {
            var report = new AnalysisService(null).ImportRuntimeTrace(options.Positional[0]);
            WriteReports(options, report, output);
            return (int)report.Assessment.Verdict;
        }
        catch (Exception ex) when (Expected(ex))
        {
            error.WriteLine($"error: {ex.Message}");
            return 3;
        }
    }

    private static void WriteReports(CliOptions options, AnalysisCase report, TextWriter output)
    {
        var json = options.ReportJsonPath;
        var html = options.ReportHtmlPath;
        if (json is not null && html is not null &&
            string.Equals(Path.GetFullPath(json), Path.GetFullPath(html), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("JSON and HTML reports must use different paths.");
        EnsureNewPath(json);
        EnsureNewPath(html);

        if (json is null && html is null)
        {
            output.Write(CaseExporter.ToJson(report));
            return;
        }
        if (json is not null) WriteNewFile(json, CaseExporter.ToJson(report));
        if (html is not null) WriteNewFile(html, CaseExporter.ToHtml(report));
        output.WriteLine(
            $"{report.Assessment.Verdict}: {report.Artifacts.Count} artifact(s), " +
            $"{report.Findings.Count} finding(s), {report.Indicators.Count} indicator(s), " +
            $"{report.Capabilities.Count} capability group(s).");
    }

    private static void EnsureNewPath(string? path)
    {
        if (path is null) return;
        if (File.Exists(path)) throw new IOException($"Refusing to overwrite '{path}'.");
    }

    private static void WriteNewFile(string path, string content)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new ArgumentException("The report path has no parent directory.", nameof(path));
        Directory.CreateDirectory(directory);
        using var stream = new FileStream(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var writer = new StreamWriter(stream, Utf8NoBom);
        writer.Write(content);
    }

    private static bool Expected(Exception exception) => exception is
        IOException or UnauthorizedAccessException or ArgumentException or AnalysisLimitException or
        JsonException or DecoderFallbackException;
}
