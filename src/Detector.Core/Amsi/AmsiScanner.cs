using System.Runtime.InteropServices;
using System.Text;
using Detector.Model;

namespace Detector.Amsi;

/// Thin wrapper over the real Windows Antimalware Scan Interface (amsi.dll).
/// Delegates the verdict to the installed AV provider (e.g. Microsoft Defender),
/// so a "malicious" result means the on-box engine flagged the content.
public sealed class AmsiScanner : IDisposable
{
    // AMSI_RESULT: values >= AMSI_RESULT_DETECTED are treated as malware.
    private const int AMSI_RESULT_DETECTED = 32768;

    private readonly IntPtr _context;
    private bool _disposed;

    public AmsiScanner(string appName = "Detector")
    {
        int hr = AmsiInitialize(appName, out _context);
        if (hr != 0)
            throw new InvalidOperationException($"AmsiInitialize failed: 0x{hr:X8}");
    }

    public static bool IsMalware(int result) => result >= AMSI_RESULT_DETECTED;

    /// Scan a raw byte buffer (file content, memory dump, ...).
    public Detection Scan(byte[] data, string target, string contentName)
    {
        EnsureNotDisposed();
        // If a session cannot be opened, fall back to a sessionless scan
        // (AmsiScanBuffer accepts a null session) rather than using an invalid one.
        bool hasSession = AmsiOpenSession(_context, out var session) == 0;
        if (!hasSession) session = IntPtr.Zero;
        try
        {
            int hr = AmsiScanBuffer(_context, data, (uint)data.Length, contentName, session, out int res);
            if (hr != 0)
                return new Detection("AMSI", target, Severity.Low, Verdict.Error,
                    "amsi.scan-error", $"AmsiScanBuffer hr=0x{hr:X8}");

            return IsMalware(res)
                ? new Detection("AMSI", target, Severity.Critical, Verdict.Malicious,
                    "amsi.detected", $"AMSI provider flagged content (result={res}).")
                : new Detection("AMSI", target, Severity.Info, Verdict.Clean,
                    "amsi.clean", $"result={res}");
        }
        finally { if (hasSession) AmsiCloseSession(_context, session); }
    }

    /// Scan a string (PowerShell script/command). AMSI expects UTF-16.
    public Detection ScanString(string content, string target, string contentName)
        => Scan(Encoding.Unicode.GetBytes(content), target, contentName);

    private void EnsureNotDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(AmsiScanner));
    }

    public void Dispose()
    {
        if (_disposed) return;
        if (_context != IntPtr.Zero) AmsiUninitialize(_context);
        _disposed = true;
    }

    [DllImport("amsi.dll", ExactSpelling = true)]
    private static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)] string appName, out IntPtr amsiContext);

    [DllImport("amsi.dll", ExactSpelling = true)]
    private static extern void AmsiUninitialize(IntPtr amsiContext);

    [DllImport("amsi.dll", ExactSpelling = true)]
    private static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

    [DllImport("amsi.dll", ExactSpelling = true)]
    private static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

    [DllImport("amsi.dll", ExactSpelling = true)]
    private static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length,
        [MarshalAs(UnmanagedType.LPWStr)] string contentName, IntPtr session, out int result);
}
