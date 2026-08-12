using System.Text.RegularExpressions;
using Detector.Model;

namespace Detector.PowerShell;

/// Regex-based heuristics for suspicious PowerShell constructs. Pure, so it is
/// unit-testable and runs on every deobfuscated layer.
public static class PsHeuristics
{
    public sealed record Hit(string Rule, Severity Severity, string Match);

    private static readonly (Regex rx, string rule, Severity sev)[] Rules =
    {
        (new(@"\bIEX\b|Invoke-Expression", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ps.iex", Severity.High),
        (new(@"Net\.WebClient|DownloadString|DownloadFile|DownloadData", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ps.webclient-download", Severity.High),
        (new(@"Start-BitsTransfer|Invoke-WebRequest|Invoke-RestMethod|\bcurl\b|\bwget\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ps.remote-fetch", Severity.Medium),
        (new(@"-e(?:ncodedcommand|ncodedcomman|ncodedcomma|ncodedcomm|ncodedcom|ncodedco|ncodedc|ncoded|ncode|ncod|nco|nc|n)?\s+[A-Za-z0-9+/=]{16,}", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ps.encodedcommand", Severity.High),
        (new(@"-w[a-z]*\s+hidden", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ps.window-hidden", Severity.Medium),
        (new(@"-nop(rofile)?\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ps.no-profile", Severity.Low),
        (new(@"-ex[a-z]*\s+bypass|-ep\s+bypass", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ps.exec-bypass", Severity.Medium),
        (new(@"Reflection\.Assembly|\[Reflection\.Assembly\]|::Load\(", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ps.reflection-load", Severity.High),
        (new(@"VirtualAlloc|WriteProcessMemory|CreateRemoteThread|memset|OpenProcess", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ps.injection-api", Severity.Critical),
        (new(@"FromBase64String", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ps.base64-decode", Severity.Medium),
        (new(@"System\.Net\.Sockets|TcpClient|-nonInteractive", RegexOptions.IgnoreCase | RegexOptions.Compiled), "ps.network-shell", Severity.Medium),
    };

    public static IReadOnlyList<Hit> Evaluate(string script)
    {
        var hits = new List<Hit>();
        foreach (var (rx, rule, sev) in Rules)
        {
            var m = rx.Match(script);
            if (m.Success) hits.Add(new Hit(rule, sev, m.Value.Trim()));
        }
        return hits;
    }
}
