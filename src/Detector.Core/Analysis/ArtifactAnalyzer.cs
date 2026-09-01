using System.Security.Cryptography;
using System.Text;
using Detector.Model;
using Detector.Trust;

namespace Detector.Analysis;

public sealed class ArtifactAnalyzer
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly AnalysisLimits _limits;

    public ArtifactAnalyzer(AnalysisLimits? limits = null) =>
        _limits = limits ?? AnalysisLimits.Default;

    public ArtifactAnalysis Analyze(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        var info = new FileInfo(fullPath);
        if (!info.Exists) throw new FileNotFoundException("Artifact was not found.", fullPath);

        var fingerprint = Fingerprint(fullPath, cancellationToken);
        var extension = info.Extension.ToLowerInvariant();
        var kind = DetectKind(fingerprint.Prefix, extension);
        var artifact = new ArtifactProfile(
            fingerprint.Sha256[..16].ToLowerInvariant(),
            info.Name,
            info.Length,
            fingerprint.Sha256,
            kind)
        {
            Path = fullPath,
            Entropy = fingerprint.Entropy
        };
        var findings = new List<Detection>();
        var coverage = new List<CoverageRecord>
        {
            new("Fingerprint", CoverageState.Completed, "Size, SHA-256 and byte entropy calculated by streaming the file.")
        };

        if (kind == ArtifactKind.PortableExecutable)
        {
            var trusted = TrustEvaluator.IsAuthenticodeTrusted(fullPath);
            artifact = artifact with { Trust = trusted ? "Trusted Authenticode signature" : "Unsigned or untrusted signature" };
            coverage.Add(new CoverageRecord(
                "Authenticode",
                CoverageState.Completed,
                trusted ? "The Windows trust provider accepted the signature chain." : "No trusted Authenticode chain was established."));
            if (!IsExpectedPeExtension(extension))
                findings.Add(new Detection(
                    "Artifact",
                    fullPath,
                    Severity.Medium,
                    Verdict.Suspicious,
                    "artifact.extension-mismatch",
                    $"PE content is stored with the '{extension}' extension.")
                { Path = fullPath });

            if (info.Length > _limits.MaximumDeepArtifactBytes)
            {
                coverage.Add(new CoverageRecord(
                    "PE/.NET metadata",
                    CoverageState.Partial,
                    $"Deep metadata analysis skipped above {_limits.MaximumDeepArtifactBytes:N0} bytes."));
            }
            else
            {
                try
                {
                    var pe = PeArtifactAnalyzer.Analyze(fullPath, artifact, _limits);
                    artifact = pe.Artifact;
                    findings.AddRange(pe.Findings);
                    coverage.Add(new CoverageRecord(
                        "PE/.NET metadata",
                        CoverageState.Completed,
                        "PE headers and managed metadata parsed without loading the image."));
                }
                catch (Exception ex) when (ex is BadImageFormatException or IOException or InvalidOperationException or
                    ArgumentOutOfRangeException or OverflowException)
                {
                    coverage.Add(new CoverageRecord("PE/.NET metadata", CoverageState.Failed, ex.Message));
                    findings.Add(new Detection(
                        "PE/.NET metadata",
                        fullPath,
                        Severity.Low,
                        Verdict.Error,
                        "artifact.pe-parse",
                        ex.Message)
                    { Path = fullPath });
                }
            }
        }
        else if (kind == ArtifactKind.CSharpSource)
        {
            if (info.Length > _limits.MaximumSourceBytes)
            {
                coverage.Add(new CoverageRecord(
                    "C# source",
                    CoverageState.Partial,
                    $"Source analysis skipped above {_limits.MaximumSourceBytes:N0} bytes."));
            }
            else
            {
                try
                {
                    var source = ReadSource(fullPath);
                    findings.AddRange(SourceAnalyzer.AnalyzeCSharp(source, fullPath));
                    coverage.Add(new CoverageRecord(
                        "C# source",
                        CoverageState.Completed,
                        "Source inspected as text; it was not compiled or executed."));
                }
                catch (DecoderFallbackException ex)
                {
                    coverage.Add(new CoverageRecord("C# source", CoverageState.Failed, ex.Message));
                }
                catch (AnalysisLimitException ex)
                {
                    coverage.Add(new CoverageRecord("C# source", CoverageState.Partial, ex.Message));
                }
            }
        }

        return new ArtifactAnalysis(artifact, findings, coverage);
    }

    private static FingerprintResult Fingerprint(string path, CancellationToken cancellationToken)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var frequencies = new long[256];
        var prefix = new byte[8];
        var prefixLength = 0;
        var buffer = new byte[128 * 1024];
        long total = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = input.Read(buffer);
            if (read == 0) break;
            if (prefixLength < prefix.Length)
            {
                var copy = Math.Min(prefix.Length - prefixLength, read);
                buffer.AsSpan(0, copy).CopyTo(prefix.AsSpan(prefixLength));
                prefixLength += copy;
            }
            hash.AppendData(buffer, 0, read);
            foreach (var value in buffer.AsSpan(0, read)) frequencies[value]++;
            total += read;
        }
        var digest = Convert.ToHexString(hash.GetHashAndReset());
        return new FingerprintResult(digest, Entropy(frequencies, total), prefix.AsSpan(0, prefixLength).ToArray());
    }

    private string ReadSource(string path)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length > _limits.MaximumSourceBytes)
            throw new AnalysisLimitException("The source file exceeds the deep-analysis limit.");
        var bytes = new byte[checked((int)input.Length)];
        input.ReadExactly(bytes);
        if (input.ReadByte() != -1)
            throw new AnalysisLimitException("The source file changed while it was being read.");
        return StrictUtf8.GetString(bytes);
    }

    private static double Entropy(long[] frequencies, long length)
    {
        if (length == 0) return 0;
        double entropy = 0;
        foreach (var count in frequencies)
        {
            if (count == 0) continue;
            var probability = (double)count / length;
            entropy -= probability * Math.Log2(probability);
        }
        return entropy;
    }

    private static ArtifactKind DetectKind(ReadOnlySpan<byte> prefix, string extension)
    {
        if (prefix.Length >= 2 && prefix[0] == 'M' && prefix[1] == 'Z')
            return ArtifactKind.PortableExecutable;
        return extension switch
        {
            ".ps1" or ".psm1" or ".psd1" => ArtifactKind.PowerShell,
            ".cs" or ".csx" => ArtifactKind.CSharpSource,
            ".jsonl" or ".ndjson" => ArtifactKind.JsonLines,
            ".txt" or ".json" or ".xml" or ".config" or ".cmd" or ".bat" => ArtifactKind.Text,
            _ => ArtifactKind.Unknown
        };
    }

    private static bool IsExpectedPeExtension(string extension) =>
        extension is ".exe" or ".dll" or ".sys" or ".scr" or ".cpl" or ".ocx";

    private sealed record FingerprintResult(string Sha256, double Entropy, byte[] Prefix);
}

public sealed record ArtifactAnalysis(
    ArtifactProfile Artifact,
    IReadOnlyList<Detection> Findings,
    IReadOnlyList<CoverageRecord> Coverage);
