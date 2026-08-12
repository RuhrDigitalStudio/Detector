using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Detector.Trust;

/// Decides whether a file/process is trustworthy enough to suppress a finding —
/// the core of false-positive reduction. Combines Authenticode verification
/// (WinVerifyTrust) with trusted-location and known-JIT-host allow-lists.
public static class TrustEvaluator
{
    // Directories whose (signed) contents we treat as low-risk.
    private static readonly string[] TrustedDirs =
    {
        @"\windows\system32\", @"\windows\syswow64\", @"\windows\winsxs\",
        @"\program files\", @"\program files (x86)\",
    };

    // Processes that legitimately allocate RWX / unbacked-exec memory (JIT / codegen),
    // so RunPE-style memory findings there are almost always false positives.
    private static readonly HashSet<string> JitHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "dotnet", "powershell", "pwsh", "powershell_ise", "w3wp", "iisexpress",
        "chrome", "msedge", "firefox", "brave", "opera",
        "java", "javaw", "node", "devenv", "code", "msbuild", "servicehub.host.clr",
        "explorer", "mmc",
    };

    /// True for a known just-in-time / codegen host (name may include ".exe").
    public static bool IsKnownJitHost(string? processName)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        var name = processName;
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            name = name[..^4];
        return JitHosts.Contains(name);
    }

    /// True if the path is under a trusted system/program location.
    public static bool IsTrustedPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.Replace('/', '\\').ToLowerInvariant();
        return TrustedDirs.Any(d => p.Contains(d));
    }

    /// Full Authenticode trust check via WinVerifyTrust (chain + trusted root).
    /// Returns false for unsigned/untrusted/missing files (fail-safe: not trusted).
    public static bool IsAuthenticodeTrusted(string? filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;
        try { return WinVerify(filePath) == 0; }
        catch { return false; }
    }

    /// True if the file is Authenticode-trusted AND signed by Microsoft.
    public static bool IsMicrosoftSigned(string? filePath)
    {
        if (!IsAuthenticodeTrusted(filePath)) return false;
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath!));
            var subject = cert.Subject;
            return subject.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase)
                || subject.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    // --- WinVerifyTrust interop ---

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private static int WinVerify(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        IntPtr pFile = Marshal.AllocHGlobal((int)fileInfo.cbStruct);
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = 2,            // WTD_UI_NONE
                fdwRevocationChecks = 0,   // WTD_REVOKE_NONE
                dwUnionChoice = 1,         // WTD_CHOICE_FILE
                pFile = pFile,
                dwStateAction = 0,         // WTD_STATEACTION_IGNORE
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = 0x00000010,  // WTD_SAFER_FLAG
                dwUIContext = 0,
            };

            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            return WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [In] ref Guid pgActionID, [In] ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }
}
