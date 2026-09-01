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

    public long MaximumDeepArtifactBytes { get; init; } = 64L * 1024 * 1024;

    public int MaximumSourceBytes { get; init; } = 4 * 1024 * 1024;

    public int MaximumPeSections { get; init; } = 96;

    public int MaximumMetadataItems { get; init; } = 20_000;

    public int MaximumRuntimeTraceCharacters { get; init; } = 64 * 1024 * 1024;

    public int MaximumRuntimeLineCharacters { get; init; } = 1 * 1024 * 1024;

    public int MaximumRuntimeErrors { get; init; } = 1_000;

    public int MaximumReportJsonCharacters { get; init; } = 16 * 1024 * 1024;
}

public sealed class AnalysisLimitException(string message) : Exception(message);
