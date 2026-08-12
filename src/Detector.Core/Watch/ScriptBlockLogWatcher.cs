using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using Detector.Amsi;
using Detector.PowerShell;
using Detector.Reporting;

namespace Detector.Watch;

/// Watches the "Microsoft-Windows-PowerShell/Operational" event log for
/// script-block logging events (ID 4104) and scans the reassembled scripts.
/// This gives the (non-elevated) watch mode PowerShell script-block visibility:
/// PowerShell auto-logs *suspicious* blocks to 4104 even without Script Block
/// Logging policy enabled, and the Operational log is readable without admin.
public sealed class ScriptBlockLogWatcher : IDisposable
{
    private const string LogName = "Microsoft-Windows-PowerShell/Operational";
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    private readonly IDetectionSink _sink;
    private readonly PowerShellScanner _ps;
    private readonly ScriptBlockAssembler _assembler = new();
    private EventLogWatcher? _watcher;

    public ScriptBlockLogWatcher(IDetectionSink sink, AmsiScanner? amsi)
    {
        _sink = sink;
        _ps = new PowerShellScanner(amsi);
    }

    /// Starts watching. Returns false (with an info message) if the log is
    /// unavailable or unreadable.
    public bool TryStart()
    {
        try
        {
            var query = new EventLogQuery(LogName, PathType.LogName, "*[System[EventID=4104]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEvent;
            _watcher.Enabled = true;
            return true;
        }
        catch (Exception ex)
        {
            _sink.Info($"Script-block log unavailable ({ex.Message}).");
            return false;
        }
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        var record = e.EventRecord;
        if (record is null) return;
        try
        {
            var (id, num, total, text) = Parse(record.ToXml());
            if (string.IsNullOrEmpty(text)) return;

            var full = _assembler.Add(id ?? "", num, total, text!);
            if (full is null) return;

            string pid = record.ProcessId?.ToString() ?? "?";
            foreach (var d in _ps.Scan(full, $"PS-ScriptBlock (log, pid {pid})"))
                _sink.Report(d);
        }
        catch { /* malformed record; skip */ }
        finally { record.Dispose(); }
    }

    private static (string? id, int num, int total, string? text) Parse(string xml)
    {
        var doc = XDocument.Parse(xml);
        string? Get(string name) => doc.Descendants(Ns + "Data")
            .FirstOrDefault(d => (string?)d.Attribute("Name") == name)?.Value;

        int num = int.TryParse(Get("MessageNumber"), out var n) ? n : 1;
        int total = int.TryParse(Get("MessageTotal"), out var t) ? t : 1;
        return (Get("ScriptBlockId"), num, total, Get("ScriptBlockText"));
    }

    public void Dispose()
    {
        try
        {
            if (_watcher is not null)
            {
                _watcher.Enabled = false;
                _watcher.Dispose();
            }
        }
        catch { /* already stopped */ }
    }
}
