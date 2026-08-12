using System.Text;
using System.Text.RegularExpressions;

namespace Detector.PowerShell;

/// Expands common PowerShell obfuscation into plain-text candidate layers.
/// Pure and side-effect free, so it is fully unit-testable without a runtime.
public static class Deobfuscator
{
    // -EncodedCommand <base64>. PowerShell accepts any unambiguous prefix
    // (-e, -en, -enc, ... -encodedcommand); match them all. UTF-16LE base64.
    private static readonly Regex EncFlag = new(
        @"-e(?:ncodedcommand|ncodedcomman|ncodedcomma|ncodedcomm|ncodedcom|ncodedco|ncodedc|ncoded|ncode|ncod|nco|nc|n)?\s+([A-Za-z0-9+/=]{16,})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Any long-ish base64 blob embedded in the text.
    private static readonly Regex B64Blob = new(
        @"[A-Za-z0-9+/]{20,}={0,2}", RegexOptions.Compiled);

    /// Returns the original text plus every successfully decoded layer,
    /// de-duplicated. Recurses up to <paramref name="maxDepth"/> to peel nested
    /// encodings (e.g. base64 that decodes to another base64).
    public static IReadOnlyList<string> Expand(string input, int maxDepth = 3)
    {
        var seen = new HashSet<string>();
        var result = new List<string>();
        var queue = new Queue<(string text, int depth)>();
        queue.Enqueue((input, 0));

        while (queue.Count > 0)
        {
            var (text, depth) = queue.Dequeue();
            if (!seen.Add(text)) continue;
            result.Add(text);
            if (depth >= maxDepth) continue;

            foreach (var decoded in DecodeCandidates(text))
                queue.Enqueue((decoded, depth + 1));
        }
        return result;
    }

    private static IEnumerable<string> DecodeCandidates(string text)
    {
        // 1) explicit -EncodedCommand payload (UTF-16LE per PowerShell spec)
        var m = EncFlag.Match(text);
        if (m.Success && TryB64(m.Groups[1].Value, Encoding.Unicode, out var enc))
            yield return enc;

        // 2) standalone base64 blobs: try UTF-16 then ASCII, keep printable ones
        foreach (Match b in B64Blob.Matches(text))
        {
            if (TryB64(b.Value, Encoding.Unicode, out var u) && IsMostlyPrintable(u))
                yield return u;
            else if (TryB64(b.Value, Encoding.ASCII, out var a) && IsMostlyPrintable(a))
                yield return a;
        }
    }

    private static bool TryB64(string s, Encoding enc, out string decoded)
    {
        decoded = "";
        if (s.Length % 4 != 0) return false;
        try
        {
            decoded = enc.GetString(Convert.FromBase64String(s));
            return decoded.Length > 0;
        }
        catch (FormatException) { return false; }
    }

    private static bool IsMostlyPrintable(string s)
    {
        if (s.Length == 0) return false;
        int printable = s.Count(c => (c >= 0x20 && c < 0x7f) || c is '\n' or '\r' or '\t');
        return (double)printable / s.Length > 0.8;
    }
}
