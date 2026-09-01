using System.Globalization;
using System.Text.Json;
using Detector.Analysis;
using Detector.Model;

namespace Detector.Runtime;

public sealed class RuntimeTraceImporter
{
    private readonly AnalysisLimits _limits;

    public RuntimeTraceImporter(AnalysisLimits? limits = null) =>
        _limits = limits ?? AnalysisLimits.Default;

    public RuntimeImportResult Import(TextReader reader, string source)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        var events = new List<TimelineEvent>();
        var findings = new List<Detection>();
        var indicators = new List<IndicatorCandidate>();
        var indicatorKeys = new HashSet<(IndicatorKind Kind, string Value)>();
        var errors = 0;
        var lineNumber = 0;
        long totalCharacters = 0;
        string? stopReason = null;

        while (true)
        {
            var line = reader.ReadLine();
            if (line is null) break;
            lineNumber++;
            totalCharacters += line.Length + 1L;
            if (totalCharacters > _limits.MaximumRuntimeTraceCharacters)
            {
                stopReason = "Runtime trace character limit reached.";
                break;
            }
            if (events.Count >= _limits.MaximumTimelineEvents)
            {
                stopReason = "Runtime timeline event limit reached.";
                break;
            }
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                if (line.Length > _limits.MaximumRuntimeLineCharacters)
                    throw new AnalysisLimitException("line exceeds the runtime event size limit");
                var timelineEvent = ParseLine(line);
                events.Add(timelineEvent);
                findings.AddRange(RuntimeEventRules.Evaluate(timelineEvent, "Runtime trace"));
                var evidenceText = string.Join(' ', timelineEvent.Properties.Values);
                foreach (var indicator in IndicatorExtractor.Extract(
                             evidenceText,
                             $"{source}, line {lineNumber}",
                             Math.Max(1, _limits.MaximumIndicators - indicators.Count)))
                {
                    if (indicators.Count >= _limits.MaximumIndicators) break;
                    if (indicatorKeys.Add((indicator.Kind, indicator.Value.ToUpperInvariant())))
                        indicators.Add(indicator);
                }
            }
            catch (Exception ex) when (ex is JsonException or FormatException or InvalidDataException or AnalysisLimitException or ArgumentException)
            {
                errors++;
                findings.Add(new Detection(
                    "Runtime trace",
                    source,
                    Severity.Low,
                    Verdict.Error,
                    "runtime.invalid-line",
                    $"Could not parse line {lineNumber}: {ex.Message}"));
                if (errors >= _limits.MaximumRuntimeErrors)
                {
                    stopReason = "Runtime trace error limit reached.";
                    break;
                }
            }
        }

        var coverage = new CoverageRecord(
            "Runtime trace",
            errors == 0 && stopReason is null ? CoverageState.Completed : CoverageState.Partial,
            stopReason ?? (errors == 0
                ? $"Imported {events.Count} event(s)."
                : $"Imported {events.Count} event(s); {errors} line(s) were invalid."));
        return new RuntimeImportResult(events, findings, indicators, [coverage]);
    }

    private TimelineEvent ParseLine(string line)
    {
        using var document = JsonDocument.Parse(line, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 16
        });
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("event must be a JSON object");

        var fields = document.RootElement.EnumerateObject()
            .GroupBy(property => property.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Last().Value, StringComparer.OrdinalIgnoreCase);
        var eventId = IntValue(fields, "EventID", "eventId");
        var eventName = StringValue(fields, "event", "EventName", "eventType") ?? EventName(eventId);
        var provider = StringValue(fields, "provider", "ProviderName") ?? "Runtime trace";
        var processId = IntValue(fields, "processId", "ProcessId", "SourceProcessId");
        var image = StringValue(fields, "processName", "SourceImage", "Image");
        var processName = ProcessName(image);
        var timestamp = Timestamp(StringValue(fields, "timestamp", "timeCreated", "UtcTime", "@timestamp"));
        var properties = ReadProperties(fields);
        return new TimelineEvent(timestamp, provider, eventName, processId, processName, properties);
    }

    private IReadOnlyDictionary<string, string> ReadProperties(IReadOnlyDictionary<string, JsonElement> fields)
    {
        var properties = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (fields.TryGetValue("properties", out var nested) && nested.ValueKind == JsonValueKind.Object)
        {
            foreach (var item in nested.EnumerateObject()) AddScalar(properties, item.Name, item.Value);
        }
        foreach (var item in fields.OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (item.Key.Equals("properties", StringComparison.OrdinalIgnoreCase)) continue;
            AddScalar(properties, item.Key, item.Value);
        }
        return properties.Take(_limits.MaximumTimelineProperties)
            .ToDictionary(item => item.Key, item => item.Value, StringComparer.OrdinalIgnoreCase);
    }

    private void AddScalar(IDictionary<string, string> properties, string name, JsonElement value)
    {
        if (properties.Count >= _limits.MaximumTimelineProperties || value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
            return;
        var text = value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText();
        if (string.IsNullOrEmpty(text)) return;
        if (name.Length > _limits.MaximumTextLength) name = name[.._limits.MaximumTextLength];
        if (text.Length > _limits.MaximumTextLength) text = text[.._limits.MaximumTextLength];
        properties[name] = text;
    }

    private static string? StringValue(IReadOnlyDictionary<string, JsonElement> fields, params string[] names)
    {
        foreach (var name in names)
        {
            if (!fields.TryGetValue(name, out var value)) continue;
            return value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText();
        }
        return null;
    }

    private static int? IntValue(IReadOnlyDictionary<string, JsonElement> fields, params string[] names)
    {
        var value = StringValue(fields, names);
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) ? number : null;
    }

    private static DateTimeOffset? Timestamp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var timestamp)
            ? timestamp
            : throw new FormatException("timestamp is invalid");
    }

    private static string? ProcessName(string? image)
    {
        if (string.IsNullOrWhiteSpace(image)) return null;
        try { return Path.GetFileNameWithoutExtension(image); }
        catch (ArgumentException) { return image; }
    }

    private static string EventName(int? eventId) => eventId switch
    {
        1 => "ProcessCreate",
        3 => "NetworkConnect",
        7 => "ImageLoad",
        8 => "CreateRemoteThread",
        10 => "ProcessAccess",
        11 => "FileCreate",
        12 or 13 or 14 => "RegistryValueSet",
        22 => "DnsQuery",
        25 => "ProcessTampering",
        int value => $"Event {value}",
        _ => "Unknown"
    };
}

public sealed record RuntimeImportResult(
    IReadOnlyList<TimelineEvent> Events,
    IReadOnlyList<Detection> Findings,
    IReadOnlyList<IndicatorCandidate> Indicators,
    IReadOnlyList<CoverageRecord> Coverage);
