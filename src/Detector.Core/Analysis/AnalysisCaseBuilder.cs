using Detector.Model;

namespace Detector.Analysis;

public sealed class AnalysisCaseBuilder
{
    private readonly AnalysisLimits _limits;
    private readonly List<ArtifactProfile> _artifacts = [];
    private readonly List<Detection> _findings = [];
    private readonly Dictionary<(IndicatorKind Kind, string Value), IndicatorAccumulator> _indicators = new();
    private readonly List<Capability> _capabilities = [];
    private readonly List<TimelineEvent> _timeline = [];
    private readonly List<CoverageRecord> _coverage = [];

    public AnalysisCaseBuilder(
        string caseId,
        string title,
        DateTimeOffset createdAt,
        AnalysisLimits? limits = null)
    {
        _limits = limits ?? AnalysisLimits.Default;
        CaseId = RequiredText(caseId, nameof(caseId));
        Title = RequiredText(title, nameof(title));
        CreatedAt = createdAt;
    }

    public string CaseId { get; }

    public string Title { get; }

    public DateTimeOffset CreatedAt { get; }

    public void AddArtifact(ArtifactProfile artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        EnsureSpace(_artifacts.Count, _limits.MaximumArtifacts, "artifacts");
        ValidateArtifact(artifact);
        _artifacts.Add(artifact);
    }

    public void AddFinding(Detection finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        EnsureSpace(_findings.Count, _limits.MaximumFindings, "findings");
        ValidateText(finding.Source, "finding source");
        ValidateText(finding.Target, "finding target");
        ValidateText(finding.Rule, "finding rule");
        ValidateText(finding.Details, "finding details");
        _findings.Add(finding);
    }

    public void AddIndicator(IndicatorKind kind, string value, string source, string context)
    {
        var normalized = NormalizeIndicator(kind, RequiredText(value, nameof(value)));
        source = RequiredText(source, nameof(source));
        context = RequiredText(context, nameof(context));
        var key = (kind, normalized.ToUpperInvariant());
        if (!_indicators.TryGetValue(key, out var accumulator))
        {
            EnsureSpace(_indicators.Count, _limits.MaximumIndicators, "indicators");
            accumulator = new IndicatorAccumulator(kind, normalized);
            _indicators.Add(key, accumulator);
        }
        accumulator.Sources.Add(source);
        accumulator.Contexts.Add(context);
    }

    public void AddCapability(Capability capability)
    {
        ArgumentNullException.ThrowIfNull(capability);
        EnsureSpace(_capabilities.Count, _limits.MaximumCapabilities, "capabilities");
        ValidateText(capability.Id, "capability id");
        ValidateText(capability.Title, "capability title");
        ValidateText(capability.Explanation, "capability explanation");
        if (capability.SupportingRules.Count > _limits.MaximumFindings)
            throw new AnalysisLimitException("A capability has too many supporting rules.");
        _capabilities.Add(capability);
    }

    public void AddTimelineEvent(TimelineEvent timelineEvent)
    {
        ArgumentNullException.ThrowIfNull(timelineEvent);
        EnsureSpace(_timeline.Count, _limits.MaximumTimelineEvents, "timeline events");
        ValidateText(timelineEvent.Provider, "timeline provider");
        ValidateText(timelineEvent.Event, "timeline event");
        if (timelineEvent.Properties.Count > _limits.MaximumTimelineProperties)
            throw new AnalysisLimitException("A timeline event has too many properties.");
        foreach (var property in timelineEvent.Properties)
        {
            ValidateText(property.Key, "timeline property name");
            ValidateText(property.Value, "timeline property value");
        }
        _timeline.Add(timelineEvent);
    }

    public void AddCoverage(string module, CoverageState state, string details)
    {
        EnsureSpace(_coverage.Count, _limits.MaximumCoverageRecords, "coverage records");
        _coverage.Add(new CoverageRecord(
            RequiredText(module, nameof(module)),
            state,
            RequiredText(details, nameof(details))));
    }

    public AnalysisCase Build()
    {
        var indicators = _indicators.Values
            .Select(item => item.Build())
            .OrderBy(item => item.Kind)
            .ThenBy(item => item.Value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var findings = _findings.OrderByDescending(item => item.Severity)
            .ThenBy(item => item.Source, StringComparer.Ordinal)
            .ThenBy(item => item.Rule, StringComparer.Ordinal)
            .ThenBy(item => item.Target, StringComparer.Ordinal).ToArray();
        var capabilities = MergeCapabilities(_capabilities.Concat(CorrelationEngine.Correlate(findings)));
        var coverage = _coverage.OrderBy(item => item.Module, StringComparer.Ordinal)
            .ThenBy(item => item.State).ToArray();
        var assessment = CaseAssessment.Create(findings, coverage, capabilities);
        return new AnalysisCase(
            AnalysisCase.CurrentSchemaVersion,
            CaseId,
            Title,
            CreatedAt,
            _artifacts.OrderBy(item => item.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.Id, StringComparer.Ordinal).ToArray(),
            findings,
            indicators,
            capabilities,
            _timeline.OrderBy(item => item.Timestamp)
                .ThenBy(item => item.Provider, StringComparer.Ordinal)
                .ThenBy(item => item.Event, StringComparer.Ordinal).ToArray(),
            coverage,
            assessment);
    }

    private static Capability[] MergeCapabilities(IEnumerable<Capability> capabilities) =>
        capabilities.GroupBy(item => item.Id, StringComparer.Ordinal)
            .Select(group =>
            {
                var strongest = group.OrderByDescending(item => item.Confidence).First();
                return strongest with
                {
                    SupportingRules = group.SelectMany(item => item.SupportingRules)
                        .Distinct(StringComparer.Ordinal).Order().ToArray()
                };
            })
            .OrderByDescending(item => item.Confidence)
            .ThenBy(item => item.Id, StringComparer.Ordinal).ToArray();

    private string RequiredText(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("Text cannot be empty.", name);
        ValidateText(value, name);
        return value.Trim();
    }

    private void ValidateArtifact(ArtifactProfile artifact)
    {
        ValidateText(artifact.Id, "artifact id");
        ValidateText(artifact.DisplayName, "artifact name");
        ValidateText(artifact.Sha256, "artifact hash");
        if (artifact.Size < 0) throw new ArgumentOutOfRangeException(nameof(artifact), "Artifact size cannot be negative.");
    }

    private void ValidateText(string value, string field)
    {
        if (value.Length > _limits.MaximumTextLength)
            throw new AnalysisLimitException($"The {field} exceeds the text limit.");
    }

    private static void EnsureSpace(int count, int maximum, string collection)
    {
        if (count >= maximum)
            throw new AnalysisLimitException($"The analysis case exceeds the {collection} limit.");
    }

    private static string NormalizeIndicator(IndicatorKind kind, string value)
    {
        value = value.Trim();
        if (kind == IndicatorKind.Url && Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            var builder = new UriBuilder(uri)
            {
                Scheme = uri.Scheme.ToLowerInvariant(),
                Host = uri.Host.ToLowerInvariant()
            };
            return builder.Uri.AbsoluteUri;
        }
        return kind is IndicatorKind.Domain or IndicatorKind.IpAddress or IndicatorKind.Hash
            ? value.ToLowerInvariant()
            : value;
    }

    private sealed class IndicatorAccumulator(IndicatorKind kind, string value)
    {
        public IndicatorKind Kind { get; } = kind;

        public string Value { get; } = value;

        public HashSet<string> Sources { get; } = new(StringComparer.Ordinal);

        public HashSet<string> Contexts { get; } = new(StringComparer.Ordinal);

        public Indicator Build() => new(
            Kind,
            Value,
            Sources.Order(StringComparer.Ordinal).ToArray(),
            Contexts.Order(StringComparer.Ordinal).ToArray());
    }
}
