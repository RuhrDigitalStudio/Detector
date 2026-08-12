using System.Management;
using Detector.Amsi;
using Detector.Model;
using Detector.PowerShell;
using Detector.Process;
using Detector.Reporting;
using SysProcess = System.Diagnostics.Process;

namespace Detector.Watch;

/// Real-time monitor. Polls the process list, diffs PIDs, and scans every newly
/// started process: PowerShell command lines get deobfuscated + AMSI-scanned,
/// and all new processes get a RunPE quick-scan shortly after start (hollowing
/// usually happens moments after launch). Works without elevation, unlike the
/// richer ETW-based <see cref="EtwSensor"/>.
public sealed class WatchService : IRealtimeMonitor
{
    private readonly IDetectionSink _reporter;
    private readonly AmsiScanner? _amsi;
    private readonly PowerShellScanner _ps;
    private readonly RunPeScanner _runpe = new();
    private readonly int _pollMs;

    private static readonly string[] PsNames = { "powershell", "pwsh", "powershell_ise" };

    public WatchService(IDetectionSink reporter, AmsiScanner? amsi, int pollMs = 750)
    {
        _reporter = reporter;
        _amsi = amsi;
        _ps = new PowerShellScanner(amsi);
        _pollMs = pollMs;
    }

    public void Run(CancellationToken token)
    {
        _reporter.Info($"watch: monitoring new processes every {_pollMs} ms.");
        if (!IsElevated())
            _reporter.Info("watch: not elevated — memory scans of other users' processes may be limited.");

        // PowerShell script-block logging (Event 4104) via the Operational log —
        // works without elevation and catches in-memory scripts.
        using var scriptBlocks = new ScriptBlockLogWatcher(_reporter, _amsi);
        if (scriptBlocks.TryStart())
            _reporter.Info("watch: PowerShell script-block logging active (event 4104).");

        var known = new HashSet<int>(SnapshotPids());

        while (!token.IsCancellationRequested)
        {
            try { Task.Delay(_pollMs, token).Wait(token); }
            catch (OperationCanceledException) { break; }

            int[] current;
            try { current = SnapshotPids(); }
            catch { continue; }

            foreach (int pid in current)
            {
                if (!known.Add(pid)) continue;
                try { Inspect(pid); }
                catch { /* process vanished or protected; ignore */ }
            }

            // Drop exited PIDs so a later recycled PID is inspected again.
            known.IntersectWith(current);
        }

        _reporter.Info("watch: stopped.");
    }

    private void Inspect(int pid)
    {
        string name;
        try { using var p = SysProcess.GetProcessById(pid); name = p.ProcessName; }
        catch { return; }

        bool isPs = PsNames.Contains(name, StringComparer.OrdinalIgnoreCase);

        if (isPs)
        {
            string? cmd = TryGetCommandLine(pid);
            if (!string.IsNullOrWhiteSpace(cmd))
                foreach (var d in _ps.Scan(cmd!, $"{name} (pid {pid})"))
                    _reporter.Report(d);
            else
                _reporter.Info($"watch: {name} (pid {pid}) started (command line unavailable).");
        }

        // RunPE quick-scan for every new process (best effort).
        try
        {
            foreach (var d in _runpe.ScanProcess(pid, name))
                _reporter.Report(d);
        }
        catch (UnauthorizedAccessException) { /* needs elevation */ }
    }

    private static int[] SnapshotPids()
    {
        var procs = SysProcess.GetProcesses();
        try
        {
            var ids = new int[procs.Length];
            for (int i = 0; i < procs.Length; i++) ids[i] = procs[i].Id;
            return ids;
        }
        finally { foreach (var p in procs) p.Dispose(); }
    }

    /// Retrieve a process's full command line via WMI. Returns null if WMI is
    /// unavailable or access is denied.
    private static string? TryGetCommandLine(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementBaseObject mo in searcher.Get())
                return mo["CommandLine"]?.ToString();
        }
        catch { /* WMI missing/denied */ }
        return null;
    }

    private static bool IsElevated()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(id);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
