using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Detector.Analysis;

public static class CaseExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        MaxDepth = 32,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static string ToJson(AnalysisCase report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return JsonSerializer.Serialize(report, JsonOptions);
    }

    public static AnalysisCase FromJson(string json, AnalysisLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(json);
        limits ??= AnalysisLimits.Default;
        if (json.Length > limits.MaximumReportJsonCharacters)
            throw new AnalysisLimitException("The JSON report exceeds the input size limit.");
        var report = JsonSerializer.Deserialize<AnalysisCase>(json, JsonOptions)
            ?? throw new InvalidDataException("The JSON report is empty.");
        Validate(report, limits);
        return report;
    }

    public static string ToHtml(AnalysisCase report)
    {
        ArgumentNullException.ThrowIfNull(report);
        static string H(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
        var html = new StringBuilder(16_384);
        html.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
            .Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
            .Append("<title>").Append(H(report.Title)).Append(" — Detector report</title>")
            .Append("<style>body{font:15px system-ui;margin:2rem;max-width:1100px;color:#172033}")
            .Append("h1,h2{color:#0b1324}table{border-collapse:collapse;width:100%;margin:1rem 0}")
            .Append("th,td{border:1px solid #d8deea;padding:.55rem;text-align:left;vertical-align:top}")
            .Append("th{background:#eef2f8}.meta{color:#55627a}.gap{color:#9b2c2c}</style></head><body>")
            .Append("<h1>").Append(H(report.Title)).Append("</h1><p class=\"meta\">Case ")
            .Append(H(report.CaseId)).Append(" · ").Append(H(report.CreatedAt.ToString("O"))).Append("</p>")
            .Append("<p>").Append(report.Artifacts.Count).Append(" artifact(s), ")
            .Append(report.Findings.Count).Append(" finding(s), ")
            .Append(report.Indicators.Count).Append(" indicator(s).</p>");

        AppendArtifacts(html, report, H);
        AppendFindings(html, report, H);
        AppendIndicators(html, report, H);
        AppendCoverage(html, report, H);
        html.Append("</body></html>");
        return html.ToString();
    }

    private static void AppendArtifacts(StringBuilder html, AnalysisCase report, Func<string?, string> h)
    {
        html.Append("<h2>Artifacts</h2><table><thead><tr><th>Name</th><th>Kind</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>");
        foreach (var item in report.Artifacts)
            html.Append("<tr><td>").Append(h(item.DisplayName)).Append("</td><td>").Append(h(item.Kind.ToString()))
                .Append("</td><td>").Append(item.Size).Append("</td><td>").Append(h(item.Sha256)).Append("</td></tr>");
        html.Append("</tbody></table>");
    }

    private static void AppendFindings(StringBuilder html, AnalysisCase report, Func<string?, string> h)
    {
        html.Append("<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Target</th><th>Details</th></tr></thead><tbody>");
        foreach (var item in report.Findings)
            html.Append("<tr><td>").Append(h(item.Severity.ToString())).Append("</td><td>").Append(h(item.Rule))
                .Append("</td><td>").Append(h(item.Target)).Append("</td><td>").Append(h(item.Details)).Append("</td></tr>");
        html.Append("</tbody></table>");
    }

    private static void AppendIndicators(StringBuilder html, AnalysisCase report, Func<string?, string> h)
    {
        html.Append("<h2>Indicators</h2><table><thead><tr><th>Kind</th><th>Value</th><th>Sources</th></tr></thead><tbody>");
        foreach (var item in report.Indicators)
            html.Append("<tr><td>").Append(h(item.Kind.ToString())).Append("</td><td>").Append(h(item.Value))
                .Append("</td><td>").Append(h(string.Join(", ", item.Sources))).Append("</td></tr>");
        html.Append("</tbody></table>");
    }

    private static void AppendCoverage(StringBuilder html, AnalysisCase report, Func<string?, string> h)
    {
        html.Append("<h2>Coverage</h2><table><thead><tr><th>Module</th><th>State</th><th>Details</th></tr></thead><tbody>");
        foreach (var item in report.Coverage)
            html.Append("<tr><td>").Append(h(item.Module)).Append("</td><td class=\"")
                .Append(item.State == CoverageState.Completed ? string.Empty : "gap").Append("\">")
                .Append(h(item.State.ToString())).Append("</td><td>").Append(h(item.Details)).Append("</td></tr>");
        html.Append("</tbody></table>");
    }

    private static void Validate(AnalysisCase report, AnalysisLimits limits)
    {
        if (report.SchemaVersion != AnalysisCase.CurrentSchemaVersion)
            throw new InvalidDataException("The analysis case schema version is not supported.");
        if (report.Artifacts is null || report.Findings is null || report.Indicators is null ||
            report.Capabilities is null || report.Timeline is null || report.Coverage is null)
            throw new InvalidDataException("The analysis case contains a null collection.");
        if (report.Artifacts.Count > limits.MaximumArtifacts || report.Findings.Count > limits.MaximumFindings ||
            report.Indicators.Count > limits.MaximumIndicators || report.Capabilities.Count > limits.MaximumCapabilities ||
            report.Timeline.Count > limits.MaximumTimelineEvents || report.Coverage.Count > limits.MaximumCoverageRecords)
            throw new AnalysisLimitException("The JSON report exceeds an analysis collection limit.");

        CheckText(report.CaseId, limits, "case id");
        CheckText(report.Title, limits, "title");
        foreach (var artifact in report.Artifacts)
        {
            if (artifact is null) throw new InvalidDataException("The artifact collection contains null.");
            CheckText(artifact.Id, limits, "artifact id");
            CheckText(artifact.DisplayName, limits, "artifact name");
            CheckText(artifact.Sha256, limits, "artifact hash");
            if (artifact.Size < 0) throw new InvalidDataException("An artifact size is negative.");
        }
        foreach (var finding in report.Findings)
        {
            if (finding is null) throw new InvalidDataException("The findings collection contains null.");
            CheckText(finding.Source, limits, "finding source");
            CheckText(finding.Target, limits, "finding target");
            CheckText(finding.Rule, limits, "finding rule");
            CheckText(finding.Details, limits, "finding details");
        }
        foreach (var indicator in report.Indicators)
        {
            if (indicator is null || indicator.Sources is null || indicator.Contexts is null)
                throw new InvalidDataException("An indicator is incomplete.");
            CheckText(indicator.Value, limits, "indicator value");
            foreach (var source in indicator.Sources) CheckText(source, limits, "indicator source");
            foreach (var context in indicator.Contexts) CheckText(context, limits, "indicator context");
        }
        foreach (var capability in report.Capabilities)
        {
            if (capability is null || capability.SupportingRules is null)
                throw new InvalidDataException("A capability is incomplete.");
            CheckText(capability.Id, limits, "capability id");
            CheckText(capability.Title, limits, "capability title");
            CheckText(capability.Explanation, limits, "capability explanation");
            foreach (var rule in capability.SupportingRules) CheckText(rule, limits, "supporting rule");
        }
        foreach (var item in report.Timeline)
        {
            if (item is null || item.Properties is null)
                throw new InvalidDataException("A timeline event is incomplete.");
            if (item.Properties.Count > limits.MaximumTimelineProperties)
                throw new AnalysisLimitException("A timeline event has too many properties.");
            CheckText(item.Provider, limits, "timeline provider");
            CheckText(item.Event, limits, "timeline event");
            foreach (var property in item.Properties)
            {
                CheckText(property.Key, limits, "timeline property name");
                CheckText(property.Value, limits, "timeline property value");
            }
        }
        foreach (var item in report.Coverage)
        {
            if (item is null) throw new InvalidDataException("The coverage collection contains null.");
            CheckText(item.Module, limits, "coverage module");
            CheckText(item.Details, limits, "coverage details");
        }
    }

    private static void CheckText(string? value, AnalysisLimits limits, string field)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new InvalidDataException($"The {field} is empty.");
        if (value.Length > limits.MaximumTextLength)
            throw new AnalysisLimitException($"The {field} exceeds the text limit.");
    }
}
