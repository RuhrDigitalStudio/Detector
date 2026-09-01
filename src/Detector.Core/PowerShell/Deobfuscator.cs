using System.Text;
using System.Text.RegularExpressions;
using Detector.Analysis;

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
    public static IReadOnlyList<string> Expand(
        string input,
        int maxDepth = 3,
        int maximumLayers = 32,
        int maximumLayerCharacters = 1_048_576)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (maxDepth < 0) throw new ArgumentOutOfRangeException(nameof(maxDepth));
        if (maximumLayers < 1) throw new ArgumentOutOfRangeException(nameof(maximumLayers));
        if (maximumLayerCharacters < 1) throw new ArgumentOutOfRangeException(nameof(maximumLayerCharacters));
        if (input.Length > maximumLayerCharacters)
            throw new AnalysisLimitException("The PowerShell input exceeds the text analysis limit.");
        var seen = new HashSet<string>();
        var result = new List<string>();
        var queue = new Queue<(string text, int depth)>();
        queue.Enqueue((input, 0));

        while (queue.Count > 0 && result.Count < maximumLayers)
        {
            var (text, depth) = queue.Dequeue();
            if (!seen.Add(text)) continue;
            result.Add(text);
            if (depth >= maxDepth) continue;

            foreach (var decoded in DecodeCandidates(text, maximumLayerCharacters))
            {
                if (decoded.Length <= maximumLayerCharacters)
                    queue.Enqueue((decoded, depth + 1));
                if (result.Count + queue.Count >= maximumLayers) break;
            }
        }
        return result;
    }

    private static IEnumerable<string> DecodeCandidates(string text, int maximumLayerCharacters)
    {
        // 1) explicit -EncodedCommand payload (UTF-16LE per PowerShell spec)
        var m = EncFlag.Match(text);
        if (m.Success && m.Groups[1].Value.Length <= (long)maximumLayerCharacters * 2 &&
            TryB64(m.Groups[1].Value, Encoding.Unicode, maximumLayerCharacters, out var enc))
            yield return enc;

        // 2) standalone base64 blobs: try UTF-16 then ASCII, keep printable ones
        foreach (Match b in B64Blob.Matches(text))
        {
            if (b.Value.Length > (long)maximumLayerCharacters * 2) continue;
            if (TryB64(b.Value, Encoding.Unicode, maximumLayerCharacters, out var u) && IsMostlyPrintable(u))
                yield return u;
            else if (TryB64(b.Value, Encoding.ASCII, maximumLayerCharacters, out var a) && IsMostlyPrintable(a))
                yield return a;
        }
    }

    private static bool TryB64(string s, Encoding enc, int maximumLayerCharacters, out string decoded)
    {
        decoded = "";
        if (s.Length % 4 != 0) return false;
        try
        {
            decoded = enc.GetString(Convert.FromBase64String(s));
            return decoded.Length is > 0 && decoded.Length <= maximumLayerCharacters;
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
