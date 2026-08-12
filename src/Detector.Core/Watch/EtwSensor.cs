using System.Security.Principal;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Detector.Amsi;
using Detector.Model;
using Detector.PowerShell;
using Detector.Process;
using Detector.Reporting;

namespace Detector.Watch;

/// Real-time behavioural sensor built on ETW (Event Tracing for Windows) — the
/// same telemetry backbone user-mode EDRs use, no kernel driver required.
/// Subscribes to process creation, image (DLL) loads and PowerShell script-block
/// events, then feeds them into the existing detection engine.
///
/// Requires elevation (ETW kernel + real-time sessions need Administrator).
public sealed class EtwSensor : IRealtimeMonitor, IDisposable
{
    private const string SessionName = "DetectorEtwSensor";
    private static readonly string[] PsImages = { "powershell.exe", "pwsh.exe", "powershell_ise.exe" };

    private readonly IDetectionSink _sink;
    private readonly AmsiScanner? _amsi;
    private readonly PowerShellScanner _ps;
    private readonly RunPeScanner _runpe = new();
    private readonly ScriptBlockAssembler _sbAssembler = new();
    private TraceEventSession? _session;
    private long _events;

    public EtwSensor(IDetectionSink sink, AmsiScanner? amsi)
    {
        _sink = sink;
        _amsi = amsi;
        _ps = new PowerShellScanner(amsi);
    }

    public static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    public void Run(CancellationToken token)
    {
        if (!IsElevated())
        {
            _sink.Info("ETW sensor requires Administrator privileges. Monitoring was not started.");
            return;
        }

        try
        {
            _session = new TraceEventSession(SessionName) { StopOnDispose = true };
        }
        catch (Exception ex)
        {
            _sink.Info($"ETW sensor session could not be started ({ex.Message}).");
            return;
        }

        using (token.Register(() => { try { _session?.Stop(); } catch { /* stopping */ } }))
        {
            try
            {
                _session.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.ImageLoad);
                _session.EnableProvider("Microsoft-Windows-PowerShell", TraceEventLevel.Verbose, ulong.MaxValue);

                _session.Source.Kernel.ProcessStart += OnProcessStart;
                _session.Source.Kernel.ImageLoad += OnImageLoad;
                _session.Source.Dynamic.All += OnDynamic;

                _sink.Info("ETW sensor running: monitoring processes, DLL loads, and PowerShell script blocks.");
                _session.Source.Process(); // blocks until the session is stopped
            }
            catch (Exception ex)
            {
                _sink.Info($"ETW sensor error: {ex.Message}");
            }
        }

        _sink.Info($"ETW sensor stopped ({_events} events processed).");
    }

    private void OnProcessStart(ProcessTraceData d)
    {
        Interlocked.Increment(ref _events);

        // Preserve process context in advanced telemetry for later review.
        _sink.Trace(TraceLevel.Verbose,
            $"proc-start {d.ProcessName} (pid {d.ProcessID}, ppid {d.ParentID}) :: {d.CommandLine}");

        // ETW provides the command line at process start, before it can be lost.
        if (IsPowerShell(d.ImageFileName) && !string.IsNullOrWhiteSpace(d.CommandLine))
            foreach (var det in _ps.Scan(d.CommandLine, $"{d.ProcessName} (pid {d.ProcessID})"))
                _sink.Report(det with { ProcessName = d.ProcessName });

        // The process can exit or deny access before this best-effort scan runs.
        try
        {
            foreach (var det in _runpe.ScanProcess(d.ProcessID, d.ProcessName))
                _sink.Report(det);
        }
        catch { /* process may have exited or be inaccessible */ }
    }

    private void OnImageLoad(ImageLoadTraceData d)
    {
        Interlocked.Increment(ref _events);
        _sink.Trace(TraceLevel.Debug, $"image-load pid {d.ProcessID} :: {d.FileName}");
        if (IsSuspiciousModulePath(d.FileName))
            _sink.Report(new Detection("ETW/Image", $"pid {d.ProcessID}", Severity.Low, Verdict.Suspicious,
                "etw.image-from-userdir", $"Module loaded from a user-writable path: {d.FileName}")
            { Path = d.FileName });
    }

    private void OnDynamic(TraceEvent d)
    {
        if (d.ProviderName != "Microsoft-Windows-PowerShell") return;
        if ((int)d.ID != 4104) return; // PowerShell script-block logging event.

        Interlocked.Increment(ref _events);
        if (d.PayloadByName("ScriptBlockText") is not string text || string.IsNullOrWhiteSpace(text))
            return;

        // Reassemble fragmented script blocks before scanning the whole script.
        string id = d.PayloadByName("ScriptBlockId") as string ?? "";
        int num = ToInt(d.PayloadByName("MessageNumber"));
        int total = ToInt(d.PayloadByName("MessageTotal"));
        var full = _sbAssembler.Add(id, num, total, text);
        if (full is null) return;

        foreach (var det in _ps.Scan(full, $"PS-ScriptBlock (pid {d.ProcessID})"))
            _sink.Report(det);
    }

    private static int ToInt(object? o) => o switch
    {
        int i => i,
        uint u => (int)u,
        byte b => b,
        short s => s,
        ushort us => us,
        long l => (int)l,
        string s2 when int.TryParse(s2, out var v) => v,
        _ => 1
    };

    private static bool IsPowerShell(string? imagePath)
    {
        if (string.IsNullOrEmpty(imagePath)) return false;
        var name = Path.GetFileName(imagePath);
        return PsImages.Any(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));
    }

    /// True for modules loaded from user-writable locations often abused by
    /// malware (Temp, AppData, Downloads, Public, ProgramData). Pure & testable.
    public static bool IsSuspiciousModulePath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.Replace('/', '\\').ToLowerInvariant();
        if (!p.EndsWith(".dll")) return false;
        string[] needles =
        {
            "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
            "\\downloads\\", "\\users\\public\\", "\\programdata\\"
        };
        return needles.Any(n => p.Contains(n));
    }

    public void Dispose()
    {
        try { _session?.Dispose(); } catch { /* already stopped */ }
    }
}
