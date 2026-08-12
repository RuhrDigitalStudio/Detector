using Detector.Amsi;
using Detector.Heuristics;
using Detector.Model;

namespace Detector.Scanning;

/// Shared file/directory scanning orchestration (EICAR + entropy heuristics +
/// AMSI), used by both the CLI and the GUI so the logic lives in one place.
public sealed class FileScanEngine
{
    /// Entropy (bits/byte) at or above which non-trivial content is flagged.
    public const double EntropySuspicious = 7.2;

    private readonly AmsiScanner? _amsi;

    public FileScanEngine(AmsiScanner? amsi) => _amsi = amsi;

    public IEnumerable<Detection> ScanFile(string path)
    {
        byte[]? bytes = null;
        string? readError = null;
        try { bytes = File.ReadAllBytes(path); }
        catch (Exception ex) { readError = ex.Message; }

        if (bytes is null)
        {
            yield return new Detection("Heuristics", path, Severity.Low, Verdict.Error,
                "io.read", readError ?? "unreadable");
            yield break;
        }

        if (ContentHeuristics.LooksLikeEicar(bytes))
            yield return new Detection("Heuristics", path, Severity.High, Verdict.Malicious,
                "heuristic.eicar", "EICAR test signature detected.");

        double entropy = ContentHeuristics.ShannonEntropy(bytes);
        if (bytes.Length >= 512 && entropy >= EntropySuspicious)
            yield return new Detection("Heuristics", path, Severity.Low, Verdict.Suspicious,
                "heuristic.high-entropy", $"High entropy ({entropy:F2} bits/byte) - packed/encrypted?")
            { Path = path };

        if (_amsi is not null)
            yield return _amsi.Scan(bytes, path, Path.GetFileName(path));
    }

    public IEnumerable<Detection> ScanDirectory(string root)
    {
        if (!Directory.Exists(root))
        {
            yield return new Detection("Heuristics", root, Severity.Low, Verdict.Error,
                "io.not-found", "Directory not found.");
            yield break;
        }

        List<string> files = new();
        string? enumError = null;
        try { files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).ToList(); }
        catch (Exception ex) { enumError = ex.Message; }

        if (enumError is not null)
        {
            yield return new Detection("Heuristics", root, Severity.Low, Verdict.Error,
                "io.enumerate", enumError);
            yield break;
        }

        foreach (var f in files)
            foreach (var d in ScanFile(f))
                yield return d;
    }
}
