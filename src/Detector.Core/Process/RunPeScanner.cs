using System.Runtime.InteropServices;
using Detector.Model;
using static Detector.Process.NativeMethods;
using SysProcess = System.Diagnostics.Process;

namespace Detector.Process;

/// Scans process virtual memory for RunPE / process-hollowing / injection
/// indicators by walking regions with VirtualQueryEx and inspecting executable
/// pages. Strictly read-only.
public sealed class RunPeScanner
{
    private static readonly nuint MbiSize = (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

    /// Scan every accessible process. <paramref name="skipped"/> returns the
    /// number of processes that could not be opened (usually needs elevation).
    public List<Detection> ScanAll(out int skipped, bool aggressive = false)
    {
        var results = new List<Detection>();
        int skippedCount = 0;
        foreach (var p in SysProcess.GetProcesses())
        {
            try
            {
                results.AddRange(ScanProcess(p.Id, p.ProcessName, aggressive));
            }
            catch (UnauthorizedAccessException) { skippedCount++; }
            catch { /* process may have exited or be protected; ignore */ }
            finally { p.Dispose(); }
        }
        skipped = skippedCount;
        return results;
    }

    /// Scan a single process by id. Throws UnauthorizedAccessException if the
    /// process cannot be opened for reading.
    public IEnumerable<Detection> ScanProcess(int pid, string name, bool aggressive = false)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero)
            throw new UnauthorizedAccessException(
                $"OpenProcess({pid}) failed: 0x{Marshal.GetLastWin32Error():X8}");

        var findings = new List<Detection>();
        try
        {
            IntPtr addr = IntPtr.Zero;
            while (VirtualQueryEx(h, addr, out var mbi, MbiSize) != 0)
            {
                ulong baseAddr = (ulong)mbi.BaseAddress.ToInt64();
                ulong region = (ulong)mbi.RegionSize.ToInt64();
                if (region == 0) break;

                bool committed = mbi.State == MEM_COMMIT;
                bool exec = (mbi.Protect & PAGE_EXEC_MASK) != 0;
                bool isPrivate = mbi.Type == MEM_PRIVATE;
                bool isImage = mbi.Type == MEM_IMAGE;
                bool isRwx = mbi.Protect == PAGE_EXECUTE_READWRITE;

                if (committed && exec)
                {
                    bool hasPe = false;
                    int toRead = (int)Math.Min(region, 0x1000UL);
                    if (toRead >= 0x40)
                    {
                        var buf = new byte[toRead];
                        // Honor the bytes-read count: even a partial read that
                        // returns the header prefix should still be inspected.
                        ReadProcessMemory(h, mbi.BaseAddress, buf, (nuint)buf.Length, out nuint read);
                        int got = (int)Math.Min((ulong)read, (ulong)buf.Length);
                        if (got >= 0x40)
                            hasPe = PeAnalyzer.HasPeHeader(buf.AsSpan(0, got));
                    }

                    var (rule, sev, details) = PeAnalyzer.Classify(isPrivate, isImage, exec, hasPe, isRwx, aggressive);
                    if (rule is not null)
                    {
                        var verdict = sev >= Severity.High ? Verdict.Malicious : Verdict.Suspicious;
                        findings.Add(new Detection("RunPE", $"{name} (pid {pid})", sev, verdict,
                            rule, $"{details} @ 0x{baseAddr:X} size=0x{region:X}")
                        { ProcessName = name });
                    }
                }

                ulong next = baseAddr + region;
                if (next <= baseAddr) break;                 // guard against overflow/wrap
                addr = new IntPtr(unchecked((long)next));
            }
        }
        finally { CloseHandle(h); }

        return findings;
    }
}
