using System.Collections.Concurrent;
using Detector.Model;
using Detector.Trust;

namespace Detector.Reporting;

/// A false-positive filter that wraps another sink. It de-duplicates repeated
/// findings and suppresses well-understood noise (Authenticode-trusted files,
/// RWX/unbacked memory inside known JIT hosts). Nothing is lost: suppressed
/// items are still emitted to the advanced trace stream.
public sealed class FilteringSink : IDetectionSink
{
    // Only these "soft" rules are eligible for allow-list suppression. Strong
    // findings (amsi.detected, heuristic.eicar, runpe.unbacked-exec-pe, …) are
    // NEVER filtered — a signed file can still be malicious.
    private static readonly HashSet<string> JitSuppressibleRules = new()
    {
        "runpe.private-rwx", "runpe.unbacked-exec", "sensor.rwx-protect",
    };
    private static readonly HashSet<string> TrustSuppressibleRules = new()
    {
        "etw.image-from-userdir", "sensor.suspicious-dll", "heuristic.high-entropy",
    };

    private readonly IDetectionSink _inner;
    private readonly bool _enabled;
    private readonly TimeSpan _dedupWindow;
    private readonly ConcurrentDictionary<string, DateTime> _recent = new();
    private long _suppressed;

    public FilteringSink(IDetectionSink inner, bool enabled = true, TimeSpan? dedupWindow = null)
    {
        _inner = inner;
        _enabled = enabled;
        _dedupWindow = dedupWindow ?? TimeSpan.FromSeconds(10);
    }

    public long Suppressed => Interlocked.Read(ref _suppressed);

    public void Report(Detection d)
    {
        if (!_enabled) { _inner.Report(d); return; }

        // Suppress short bursts of identical findings before applying trust rules.
        string key = $"{d.Source}|{d.Rule}|{d.Target}";
        var now = DateTime.UtcNow;
        if (_recent.TryGetValue(key, out var last) && now - last < _dedupWindow)
        {
            Interlocked.Increment(ref _suppressed);
            _inner.Trace(TraceLevel.Debug, $"[dedup] {d.Rule} · {d.Target}");
            return;
        }
        _recent[key] = now;
        Prune(now);

        // Known-good trust and JIT context may suppress only soft findings.
        var reason = SuppressionReason(d);
        if (reason is not null)
        {
            Interlocked.Increment(ref _suppressed);
            _inner.Trace(TraceLevel.Verbose, $"[filtered:{reason}] {d.Rule} · {d.Target} — {d.Details}");
            return;
        }

        _inner.Report(d);
    }

    public void Info(string message) => _inner.Info(message);
    public void Trace(TraceLevel level, string message) => _inner.Trace(level, message);

    private static string? SuppressionReason(Detection d)
    {
        if (JitSuppressibleRules.Contains(d.Rule))
        {
            string? proc = d.ProcessName ?? ExtractProcessName(d.Target);
            if (TrustEvaluator.IsKnownJitHost(proc)) return "jit-host";
        }

        if (TrustSuppressibleRules.Contains(d.Rule))
        {
            string? path = d.Path ?? ExtractPath(d.Details) ?? ExtractPath(d.Target);
            if (path is not null &&
                (TrustEvaluator.IsAuthenticodeTrusted(path) || TrustEvaluator.IsTrustedPath(path)))
                return "trusted-file";
        }
        return null;
    }

    // A process target is rendered as "name (pid 1234)"; file paths are not names.
    private static string? ExtractProcessName(string target)
    {
        int idx = target.IndexOf(" (pid", StringComparison.OrdinalIgnoreCase);
        if (idx > 0) return target[..idx];
        return target.Contains('\\') ? null : target;
    }

    // Extract the first drive-qualified path token, if any.
    private static string? ExtractPath(string s)
    {
        if (string.IsNullOrEmpty(s)) return null;
        int i = s.IndexOf(":\\", StringComparison.Ordinal);
        return i >= 1 ? s[(i - 1)..].Trim() : null;
    }

    private void Prune(DateTime now)
    {
        if (_recent.Count < 512) return;
        foreach (var kv in _recent)
            if (now - kv.Value > _dedupWindow) _recent.TryRemove(kv.Key, out _);
    }
}
