namespace Detector.Analysis;

public sealed record AnalysisLimits
{
    public static AnalysisLimits Default { get; } = new();

    public int MaximumArtifacts { get; init; } = 4_096;

    public int MaximumFindings { get; init; } = 50_000;

    public int MaximumIndicators { get; init; } = 20_000;

    public int MaximumCapabilities { get; init; } = 1_024;

    public int MaximumTimelineEvents { get; init; } = 100_000;

    public int MaximumTimelineProperties { get; init; } = 64;

    public int MaximumCoverageRecords { get; init; } = 4_096;

    public int MaximumTextLength { get; init; } = 16_384;

    public int MaximumReportJsonCharacters { get; init; } = 16 * 1024 * 1024;
}

public sealed class AnalysisLimitException(string message) : Exception(message);
