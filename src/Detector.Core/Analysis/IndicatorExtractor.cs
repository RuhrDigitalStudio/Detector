using System.Net;
using System.Text.RegularExpressions;

namespace Detector.Analysis;

public sealed record IndicatorCandidate(IndicatorKind Kind, string Value, string Context);

public static class IndicatorExtractor
{
    private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;
    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(250);
    private static readonly Regex UrlPattern = new(@"\bhttps?://[^\s'""<>]+", Options, Timeout);
    private static readonly Regex DomainPattern = new(@"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])", Options, Timeout);
    private static readonly Regex IpPattern = new(@"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", Options, Timeout);
    private static readonly Regex RegistryPattern = new(@"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG):?\\[^\s'"";,]+", Options, Timeout);
    private static readonly Regex FilePattern = new(@"\b[A-Za-z]:\\[^\s'""<>|;,]+", Options, Timeout);
    private static readonly string[] CommandNames =
    [
        "powershell", "pwsh", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript"
    ];
    private static readonly HashSet<string> DomainSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "at", "ai", "app", "biz", "ch", "cloud", "cn", "co", "com", "de", "dev", "edu", "eu",
        "example", "fr", "gov", "info", "invalid", "io", "me", "mil", "net", "nl", "online", "org",
        "pl", "ru", "site", "tech", "test", "top", "ua", "uk", "xyz"
    };

    public static IReadOnlyList<IndicatorCandidate> Extract(
        string text,
        string source,
        int maximumResults = 2_000)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        if (maximumResults < 1) throw new ArgumentOutOfRangeException(nameof(maximumResults));
        var results = new List<IndicatorCandidate>();
        var seen = new HashSet<(IndicatorKind Kind, string Value)>();

        AddMatches(UrlPattern, text, IndicatorKind.Url, source, maximumResults, results, seen, NormalizeUrl);
        AddMatches(DomainPattern, text, IndicatorKind.Domain, source, maximumResults, results, seen, NormalizeDomain);
        AddMatches(IpPattern, text, IndicatorKind.IpAddress, source, maximumResults, results, seen,
            value => IPAddress.TryParse(value, out var address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                ? address.ToString()
                : null);
        AddMatches(RegistryPattern, text, IndicatorKind.RegistryPath, source, maximumResults, results, seen, TrimPunctuation);
        AddMatches(FilePattern, text, IndicatorKind.FilePath, source, maximumResults, results, seen, TrimPunctuation);

        if (results.Count < maximumResults)
        {
            var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
            for (var lineNumber = 0; lineNumber < lines.Length && results.Count < maximumResults; lineNumber++)
            {
                var line = lines[lineNumber].Trim();
                if (line.Length == 0 || !CommandNames.Any(name => line.Contains(name, StringComparison.OrdinalIgnoreCase)))
                    continue;
                if (line.Length > 512) line = line[..509] + "...";
                Add(IndicatorKind.Command, line, $"{source}, line {lineNumber + 1}", results, seen);
            }
        }
        return results;
    }

    private static void AddMatches(
        Regex regex,
        string text,
        IndicatorKind kind,
        string source,
        int maximum,
        List<IndicatorCandidate> results,
        HashSet<(IndicatorKind Kind, string Value)> seen,
        Func<string, string?> normalize)
    {
        try
        {
            foreach (Match match in regex.Matches(text))
            {
                if (results.Count >= maximum) break;
                var value = normalize(match.Value);
                if (string.IsNullOrWhiteSpace(value)) continue;
                Add(kind, value, $"{source}, offset {match.Index}", results, seen);
            }
        }
        catch (RegexMatchTimeoutException) { }
    }

    private static void Add(
        IndicatorKind kind,
        string value,
        string context,
        List<IndicatorCandidate> results,
        HashSet<(IndicatorKind Kind, string Value)> seen)
    {
        var key = (kind, value.ToUpperInvariant());
        if (seen.Add(key)) results.Add(new IndicatorCandidate(kind, value, context));
    }

    private static string? NormalizeUrl(string value)
    {
        value = TrimPunctuation(value);
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            return null;
        var builder = new UriBuilder(uri)
        {
            Scheme = uri.Scheme.ToLowerInvariant(),
            Host = uri.Host.ToLowerInvariant()
        };
        return builder.Uri.AbsoluteUri;
    }

    private static string? NormalizeDomain(string value)
    {
        var normalized = value.ToLowerInvariant();
        var extension = Path.GetExtension(normalized);
        if (extension is ".exe" or ".dll" or ".sys" or ".ps1" or ".psm1" or ".cmd" or ".bat" or
            ".scr" or ".cpl" or ".ocx") return null;
        var separator = normalized.LastIndexOf('.');
        return separator >= 0 && DomainSuffixes.Contains(normalized[(separator + 1)..]) ? normalized : null;
    }

    private static string TrimPunctuation(string value) =>
        value.TrimEnd('.', ',', ';', ':', ')', ']', '}');
}
