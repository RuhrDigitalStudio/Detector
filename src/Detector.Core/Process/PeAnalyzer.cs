using Detector.Model;

namespace Detector.Process;

/// Pure logic for classifying a process memory region. Kept separate from the
/// native scanner so the RunPE decision rules are unit-testable.
public static class PeAnalyzer
{
    /// True if the buffer starts with a DOS "MZ" header whose e_lfanew points to
    /// a "PE\0\0" signature — i.e. a full PE image mapped into this region.
    public static bool HasPeHeader(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 0x40 || buf[0] != (byte)'M' || buf[1] != (byte)'Z') return false;
        int lfanew = BitConverter.ToInt32(buf.Slice(0x3C, 4));
        // Bound-check written to avoid integer overflow on hostile lfanew values.
        if (lfanew <= 0 || lfanew > buf.Length - 4) return false;
        return buf[lfanew] == (byte)'P' && buf[lfanew + 1] == (byte)'E'
            && buf[lfanew + 2] == 0 && buf[lfanew + 3] == 0;
    }

    /// Classify one committed, executable region. Returns rule == null if benign.
    ///
    /// Signal strength (strongest first):
    ///   1. PE header in private memory  -> classic RunPE / hollowing (very low FP),
    ///      reported by default.
    ///   2. Private RWX                   -> possible injected shellcode, BUT also
    ///      produced by JIT runtimes (.NET/Java/JS). Opt-in (aggressive).
    ///   3. Any unbacked executable page  -> weakest; legit JIT/thunks trip it.
    ///      Opt-in (aggressive).
    public static (string? rule, Severity severity, string details) Classify(
        bool isPrivate, bool isImage, bool isExecutable, bool hasPe, bool isRwx, bool aggressive = false)
    {
        if (!isExecutable)
            return (null, Severity.Info, "");

        // Executable + PE header in private (non-image-backed) memory == classic
        // RunPE / process hollowing: an entire PE was written into raw memory.
        // Near-zero false positives, so this is the default detection.
        if (hasPe && isPrivate && !isImage)
            return ("runpe.unbacked-exec-pe", Severity.Critical,
                    "Private executable region contains a PE image (process hollowing / RunPE).");

        // The remaining signals are meaningful but noisy on managed/JIT processes,
        // so they only fire in aggressive mode.
        if (!aggressive)
            return (null, Severity.Info, "");

        // Private RWX memory is a hallmark of injected shellcode (also JIT).
        if (isRwx && isPrivate && !isImage)
            return ("runpe.private-rwx", Severity.High,
                    "Private RWX region - injected shellcode? (also common in JIT runtimes).");

        // Executable memory not backed by any mapped image file on disk.
        if (!isImage)
            return ("runpe.unbacked-exec", Severity.Low,
                    "Executable memory not backed by a mapped image file.");

        return (null, Severity.Info, "");
    }
}
