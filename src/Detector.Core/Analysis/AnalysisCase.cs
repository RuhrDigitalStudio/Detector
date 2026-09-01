using System.Text.Json.Serialization;
using Detector.Model;

namespace Detector.Analysis;

public enum ArtifactKind
{
    Unknown,
    Text,
    PowerShell,
    CSharpSource,
    PortableExecutable,
    ManagedAssembly,
    JsonLines
}

public enum IndicatorKind
{
    Url,
    Domain,
    IpAddress,
    FilePath,
    RegistryPath,
    Mutex,
    Command,
    Hash
}

public enum Confidence
{
    Low,
    Medium,
    High
}

public enum CoverageState
{
    Completed,
    Partial,
    Unavailable,
    Failed
}

public sealed record PeSectionProfile(
    string Name,
    int VirtualSize,
    int RawSize,
    double Entropy,
    string Characteristics);

public sealed record ApiReference(string Family, string Member, string Evidence);

public sealed record ArtifactProfile(
    string Id,
    string DisplayName,
    long Size,
    string Sha256,
    ArtifactKind Kind)
{
    public string? Path { get; init; }

    public string? Architecture { get; init; }

    public string? TargetFramework { get; init; }

    public string? EntryPoint { get; init; }

    public string? Trust { get; init; }

    public double Entropy { get; init; }

    public string? AssemblyName { get; init; }

    public string? AssemblyVersion { get; init; }

    public string? Subsystem { get; init; }

    public DateTimeOffset? PeTimestamp { get; init; }

    public IReadOnlyList<PeSectionProfile> Sections { get; init; } = [];

    public IReadOnlyList<string> AssemblyReferences { get; init; } = [];

    public IReadOnlyList<string> DeclaredTypes { get; init; } = [];

    public IReadOnlyList<string> DeclaredMethods { get; init; } = [];

    public IReadOnlyList<string> NativeImports { get; init; } = [];

    public IReadOnlyList<ApiReference> ApiReferences { get; init; } = [];
}

public sealed class Indicator : IEquatable<Indicator>
{
    [JsonConstructor]
    public Indicator(
        IndicatorKind kind,
        string value,
        IReadOnlyList<string> sources,
        IReadOnlyList<string> contexts)
    {
        Kind = kind;
        Value = value;
        Sources = sources;
        Contexts = contexts;
    }

    public IndicatorKind Kind { get; }

    public string Value { get; }

    public IReadOnlyList<string> Sources { get; }

    public IReadOnlyList<string> Contexts { get; }

    public bool Equals(Indicator? other) =>
        other is not null &&
        Kind == other.Kind &&
        string.Equals(Value, other.Value, StringComparison.Ordinal) &&
        Sources.SequenceEqual(other.Sources, StringComparer.Ordinal) &&
        Contexts.SequenceEqual(other.Contexts, StringComparer.Ordinal);

    public override bool Equals(object? obj) => Equals(obj as Indicator);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Kind);
        hash.Add(Value, StringComparer.Ordinal);
        foreach (var source in Sources) hash.Add(source, StringComparer.Ordinal);
        foreach (var context in Contexts) hash.Add(context, StringComparer.Ordinal);
        return hash.ToHashCode();
    }
}

public sealed record Capability(
    string Id,
    string Title,
    Confidence Confidence,
    string Explanation,
    IReadOnlyList<string> SupportingRules);

public sealed record TimelineEvent(
    DateTimeOffset? Timestamp,
    string Provider,
    string Event,
    int? ProcessId,
    string? ProcessName,
    IReadOnlyDictionary<string, string> Properties);

public sealed record CoverageRecord(string Module, CoverageState State, string Details);

public sealed record AnalysisCase(
    int SchemaVersion,
    string CaseId,
    string Title,
    DateTimeOffset CreatedAt,
    IReadOnlyList<ArtifactProfile> Artifacts,
    IReadOnlyList<Detection> Findings,
    IReadOnlyList<Indicator> Indicators,
    IReadOnlyList<Capability> Capabilities,
    IReadOnlyList<TimelineEvent> Timeline,
    IReadOnlyList<CoverageRecord> Coverage)
{
    public const int CurrentSchemaVersion = 1;

    [JsonIgnore]
    public bool HasCoverageGaps => Coverage.Any(item => item.State != CoverageState.Completed);
}
