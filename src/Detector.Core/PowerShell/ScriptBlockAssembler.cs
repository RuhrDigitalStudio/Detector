namespace Detector.PowerShell;

/// Reassembles PowerShell script-block logging events (Event ID 4104). Large or
/// obfuscated scripts are split across several events keyed by ScriptBlockId with
/// MessageNumber / MessageTotal; scanning a single fragment would miss patterns
/// that straddle fragment boundaries, so we buffer and reassemble the whole
/// script, and de-duplicate by ScriptBlockId. Thread-safe.
public sealed class ScriptBlockAssembler
{
    private sealed class Partial
    {
        public required string?[] Parts;
        public int Have;
    }

    private readonly Dictionary<string, Partial> _pending = new();
    private readonly HashSet<string> _completed = new();
    private readonly object _lock = new();

    /// Feeds one fragment. Returns the full reassembled script once the last
    /// fragment for its ScriptBlockId arrives, otherwise null.
    public string? Add(string scriptBlockId, int messageNumber, int messageTotal, string text)
    {
        // Without a correlation id, a single fragment cannot be assembled further.
        if (string.IsNullOrEmpty(scriptBlockId))
            return messageTotal <= 1 ? text : null;

        lock (_lock)
        {
            if (_completed.Contains(scriptBlockId)) return null;

            if (messageTotal <= 1)
            {
                MarkDone(scriptBlockId);
                return text;
            }

            if (!_pending.TryGetValue(scriptBlockId, out var p))
            {
                p = new Partial { Parts = new string?[messageTotal] };
                _pending[scriptBlockId] = p;
            }

            int idx = messageNumber - 1; // Event numbering starts at one.
            if (idx < 0 || idx >= p.Parts.Length) return null;
            if (p.Parts[idx] is null) { p.Parts[idx] = text; p.Have++; }

            if (p.Have < p.Parts.Length) return null;

            _pending.Remove(scriptBlockId);
            MarkDone(scriptBlockId);
            return string.Concat(p.Parts);
        }
    }

    // Bound the de-duplication set for long-running monitors.
    private void MarkDone(string id)
    {
        _completed.Add(id);
        if (_completed.Count > 4096) _completed.Clear();
    }
}
