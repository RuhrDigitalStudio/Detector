using System.Text;
using Detector.Amsi;
using Detector.Heuristics;
using Detector.Model;
using Detector.Runtime;

namespace Detector.Analysis;

public sealed class AnalysisService
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly AmsiScanner? _amsi;
    private readonly AnalysisLimits _limits;
    private readonly ArtifactAnalyzer _artifactAnalyzer;
    private readonly string _amsiUnavailableReason;

    public AnalysisService(
        AmsiScanner? amsi,
        AnalysisLimits? limits = null,
        string amsiUnavailableReason = "AMSI was disabled or no provider was available.")
    {
        _amsi = amsi;
        _limits = limits ?? AnalysisLimits.Default;
        _artifactAnalyzer = new ArtifactAnalyzer(_limits);
        _amsiUnavailableReason = amsiUnavailableReason;
    }

    public AnalysisCase AnalyzePath(
        string path,
        string? title = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        var builder = NewCase(title ?? DisplayName(fullPath));
        if (!File.Exists(fullPath) && !Directory.Exists(fullPath))
        {
            builder.AddFinding(new Detection("Analysis", fullPath, Severity.Low, Verdict.Error,
                "analysis.input-not-found", "The analysis input does not exist."));
            builder.AddCoverage("Input enumeration", CoverageState.Failed, "The selected path does not exist.");
            return builder.Build();
        }

        var files = File.Exists(fullPath)
            ? [fullPath]
            : EnumerateFiles(fullPath, builder, cancellationToken);
        if (File.Exists(fullPath))
            builder.AddCoverage("Input enumeration", CoverageState.Completed, "One file selected.");
        if (_amsi is null && files.Count > 0)
            builder.AddCoverage("AMSI", CoverageState.Unavailable, _amsiUnavailableReason);

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AnalyzeFile(file, builder, cancellationToken);
        }
        return builder.Build();
    }

    public AnalysisCase ImportRuntimeTrace(
        string path,
        string? title = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        var builder = NewCase(title ?? $"Runtime trace — {DisplayName(fullPath)}");
        if (!File.Exists(fullPath))
        {
            builder.AddFinding(new Detection("Runtime trace", fullPath, Severity.Low, Verdict.Error,
                "analysis.input-not-found", "The runtime trace does not exist."));
            builder.AddCoverage("Runtime trace", CoverageState.Failed, "The selected trace does not exist.");
            return builder.Build();
        }

        try
        {
            var artifact = _artifactAnalyzer.Analyze(fullPath, cancellationToken);
            AddArtifact(builder, artifact);
            using var input = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var reader = new StreamReader(input, StrictUtf8, detectEncodingFromByteOrderMarks: true,
                bufferSize: 16 * 1024, leaveOpen: false);
            var imported = new RuntimeTraceImporter(_limits).Import(reader, fullPath);
            foreach (var item in imported.Events) builder.AddTimelineEvent(item);
            foreach (var item in imported.Findings) builder.AddFinding(item);
            foreach (var item in imported.Indicators)
                builder.AddIndicator(item.Kind, item.Value, "Runtime trace", item.Context);
            foreach (var item in imported.Coverage) builder.AddCoverage(item.Module, item.State, item.Details);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DecoderFallbackException or
            AnalysisLimitException or OperationCanceledException)
        {
            if (ex is OperationCanceledException) throw;
            builder.AddFinding(new Detection("Runtime trace", fullPath, Severity.Low, Verdict.Error,
                "runtime.import-error", ex.Message));
            builder.AddCoverage("Runtime trace", CoverageState.Failed, ex.Message);
        }
        return builder.Build();
    }

    private void AnalyzeFile(string path, AnalysisCaseBuilder builder, CancellationToken cancellationToken)
    {
        ArtifactAnalysis analysis;
        try
        {
            analysis = _artifactAnalyzer.Analyze(path, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or BadImageFormatException or
            AnalysisLimitException or ArgumentException)
        {
            builder.AddFinding(new Detection("Analysis", path, Severity.Low, Verdict.Error,
                "artifact.analysis-error", ex.Message));
            builder.AddCoverage($"{DisplayName(path)} / Artifact", CoverageState.Failed, ex.Message);
            return;
        }

        AddArtifact(builder, analysis);
        if (analysis.Artifact.Size >= 512 && analysis.Artifact.Entropy >= 7.2)
            builder.AddFinding(new Detection("Heuristics", path, Severity.Low, Verdict.Suspicious,
                "heuristic.high-entropy", $"High whole-file entropy ({analysis.Artifact.Entropy:F2} bits/byte).")
            { Path = path });

        byte[]? bytes;
        try
        {
            bytes = ReadForContentScan(path, builder);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OverflowException)
        {
            builder.AddFinding(new Detection("Content scan", path, Severity.Low, Verdict.Error,
                "io.read", ex.Message));
            builder.AddCoverage($"{DisplayName(path)} / Content scan", CoverageState.Failed, ex.Message);
            return;
        }
        if (bytes is null) return;
        if (ContentHeuristics.LooksLikeEicar(bytes))
            builder.AddFinding(new Detection("Heuristics", path, Severity.High, Verdict.Malicious,
                "heuristic.eicar", "EICAR test signature detected.")
            { Path = path });
        if (_amsi is not null)
        {
            var result = _amsi.Scan(bytes, path, Path.GetFileName(path));
            builder.AddFinding(result);
            builder.AddCoverage(
                $"{DisplayName(path)} / AMSI",
                result.Verdict == Verdict.Error ? CoverageState.Failed : CoverageState.Completed,
                result.Details);
        }
    }

    private byte[]? ReadForContentScan(string path, AnalysisCaseBuilder builder)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length > _limits.MaximumAmsiBytes)
        {
            builder.AddCoverage(
                $"{DisplayName(path)} / Content scan",
                CoverageState.Partial,
                $"AMSI and byte-signature checks skipped above {_limits.MaximumAmsiBytes:N0} bytes.");
            return null;
        }
        var bytes = new byte[checked((int)input.Length)];
        input.ReadExactly(bytes);
        return bytes;
    }

    private static void AddArtifact(AnalysisCaseBuilder builder, ArtifactAnalysis analysis)
    {
        builder.AddArtifact(analysis.Artifact);
        foreach (var item in analysis.Findings) builder.AddFinding(item);
        foreach (var item in analysis.Indicators)
            builder.AddIndicator(item.Kind, item.Value, analysis.Artifact.DisplayName, item.Context);
        foreach (var item in analysis.Coverage)
            builder.AddCoverage($"{analysis.Artifact.DisplayName} / {item.Module}", item.State, item.Details);
    }

    private List<string> EnumerateFiles(
        string root,
        AnalysisCaseBuilder builder,
        CancellationToken cancellationToken)
    {
        var files = new List<string>();
        var truncated = false;
        try
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                ReturnSpecialDirectories = false,
                AttributesToSkip = FileAttributes.ReparsePoint
            };
            foreach (var file in Directory.EnumerateFiles(root, "*", options))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (files.Count >= _limits.MaximumArtifacts)
                {
                    truncated = true;
                    break;
                }
                files.Add(file);
            }
            files.Sort(StringComparer.OrdinalIgnoreCase);
            builder.AddCoverage(
                "Input enumeration",
                truncated ? CoverageState.Partial : CoverageState.Completed,
                truncated
                    ? $"Stopped after {_limits.MaximumArtifacts:N0} files."
                    : $"Selected {files.Count:N0} file(s); reparse points are excluded.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            builder.AddCoverage("Input enumeration", CoverageState.Failed, ex.Message);
            builder.AddFinding(new Detection("Analysis", root, Severity.Low, Verdict.Error,
                "analysis.enumeration-error", ex.Message));
        }
        return files;
    }

    private static AnalysisCaseBuilder NewCase(string title) =>
        new(Guid.NewGuid().ToString("N"), title, DateTimeOffset.UtcNow);

    private static string DisplayName(string path)
    {
        var name = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return string.IsNullOrWhiteSpace(name) ? path : name;
    }
}
