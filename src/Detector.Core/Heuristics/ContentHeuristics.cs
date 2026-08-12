using System.Text;

namespace Detector.Heuristics;

/// AV-independent content checks: Shannon entropy (packed/encrypted payloads)
/// and the EICAR test signature. Pure functions, unit-testable.
public static class ContentHeuristics
{
    /// Official EICAR anti-malware test string (harmless by design).
    public const string EicarSignature =
        @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    /// Shannon entropy in bits/byte, range 0 (uniform) .. 8 (random).
    public static double ShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> freq = stackalloc int[256];
        foreach (var b in data) freq[b]++;
        double entropy = 0, len = data.Length;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            double p = f / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    public static bool LooksLikeEicar(ReadOnlySpan<byte> data)
        => IndexOf(data, Encoding.ASCII.GetBytes(EicarSignature)) >= 0;

    private static int IndexOf(ReadOnlySpan<byte> hay, ReadOnlySpan<byte> needle)
    {
        if (needle.Length == 0 || hay.Length < needle.Length) return -1;
        for (int i = 0; i <= hay.Length - needle.Length; i++)
            if (hay.Slice(i, needle.Length).SequenceEqual(needle)) return i;
        return -1;
    }
}
