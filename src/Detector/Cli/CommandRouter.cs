using Detector.Amsi;
using Detector.Heuristics;
using Detector.Model;
using Detector.PowerShell;
using Detector.Process;
using Detector.Reporting;
using Detector.Scanning;
using Detector.Watch;

namespace Detector.Cli;

/// Parses arguments, builds shared services (AMSI, reporter) and dispatches to
/// the requested command. Returns the process exit code.
public static class CommandRouter
{
    public static int Run(string[] args)
    {
        var opts = CliOptions.Parse(args);
        if (opts.Error is not null)
        {
            Console.Error.WriteLine($"error: {opts.Error}");
            return 3;
        }
        if (opts.Command is null or "-h" or "--help" or "help")
        {
            PrintUsage();
            return 0;
        }
        // Runtime evidence import is offline and does not submit the trace to
        // AMSI. Route it before provider initialization to keep that boundary explicit.
        if (opts.Command == "import-trace")
            return CaseCommandRunner.ImportTrace(opts, Console.Out, Console.Error);

        var reporter = new Reporter(opts.JsonPath, opts.Verbosity);
        // The false-positive filter wraps the reporter unless disabled. Findings
        // report into `sink`; summary/exit-code come from `reporter`.
        IDetectionSink sink = opts.NoFilter ? reporter : new FilteringSink(reporter);

        AmsiScanner? amsi = null;
        if (!opts.NoAmsi)
        {
            try { amsi = new AmsiScanner(); }
            catch (Exception ex)
            {
                reporter.Info($"warn: AMSI unavailable ({ex.Message}).");
                reporter.Info("      No active antimalware provider — is Microsoft Defender (or another AV) enabled?");
                reporter.Info("      Continuing with built-in heuristics only.");
            }
        }

        try
        {
            switch (opts.Command)
            {
                case "analyze": return CaseCommandRunner.Analyze(opts, amsi, Console.Out, Console.Error);
                case "scan-file": return ScanFile(sink, reporter, amsi, opts.Positional);
                case "scan-dir": return ScanDir(sink, reporter, amsi, opts.Positional);
                case "scan-ps": return ScanPs(sink, reporter, amsi, opts.Positional);
                case "scan-proc": return ScanProc(sink, reporter, opts.Positional, opts.Aggressive);
                case "watch": return Watch(sink, reporter, amsi);
                case "monitor": return Monitor(sink, reporter, amsi);
                case "selftest": return SelfTest(sink, reporter, amsi);
                default:
                    Console.Error.WriteLine($"Unknown command: {opts.Command}");
                    PrintUsage();
                    return 3;
            }
        }
        finally { amsi?.Dispose(); }
    }

    private static int ScanFile(IDetectionSink sink, Reporter reporter, AmsiScanner? amsi, List<string> pos)
    {
        if (pos.Count < 1) { Console.Error.WriteLine("usage: detector scan-file <path>"); return 3; }
        foreach (var d in new FileScanEngine(amsi).ScanFile(pos[0]))
            sink.Report(d);
        reporter.Summary();
        return reporter.ExitCode;
    }

    private static int ScanDir(IDetectionSink sink, Reporter reporter, AmsiScanner? amsi, List<string> pos)
    {
        if (pos.Count < 1) { Console.Error.WriteLine("usage: detector scan-dir <path>"); return 3; }
        foreach (var d in new FileScanEngine(amsi).ScanDirectory(pos[0]))
            sink.Report(d);
        reporter.Summary();
        return reporter.ExitCode;
    }

    private static int ScanPs(IDetectionSink sink, Reporter reporter, AmsiScanner? amsi, List<string> pos)
    {
        if (pos.Count < 1) { Console.Error.WriteLine("usage: detector scan-ps <path|->"); return 3; }
        string target = pos[0];
        string script;
        try
        {
            script = target == "-" ? Console.In.ReadToEnd() : File.ReadAllText(target);
        }
        catch (Exception ex)
        {
            sink.Report(new Detection("PowerShell", target, Severity.Low, Verdict.Error,
                "io.read", ex.Message));
            reporter.Summary();
            return reporter.ExitCode;
        }

        var scanner = new PowerShellScanner(amsi);
        foreach (var d in scanner.Scan(script, target == "-" ? "<stdin>" : target))
            sink.Report(d);

        reporter.Summary();
        return reporter.ExitCode;
    }

    private static int ScanProc(IDetectionSink sink, Reporter reporter, List<string> pos, bool aggressive)
    {
        var scanner = new RunPeScanner();
        if (pos.Count < 1 || pos[0].Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            reporter.Info("scan-proc: scanning all accessible processes...");
            var findings = scanner.ScanAll(out int skipped, aggressive);
            foreach (var d in findings) sink.Report(d);
            if (skipped > 0)
                reporter.Info($"scan-proc: {skipped} process(es) skipped (access denied — run elevated for full coverage).");
        }
        else if (int.TryParse(pos[0], out int pid))
        {
            try
            {
                using var p = System.Diagnostics.Process.GetProcessById(pid);
                foreach (var d in scanner.ScanProcess(pid, p.ProcessName, aggressive)) sink.Report(d);
            }
            catch (UnauthorizedAccessException)
            {
                sink.Report(new Detection("RunPE", $"pid {pid}", Severity.Low, Verdict.Error,
                    "proc.access-denied", "Access denied — run elevated."));
            }
            catch (ArgumentException)
            {
                sink.Report(new Detection("RunPE", $"pid {pid}", Severity.Low, Verdict.Error,
                    "proc.not-found", "No such process."));
            }
        }
        else
        {
            Console.Error.WriteLine("usage: detector scan-proc <pid|all>");
            return 3;
        }

        reporter.Summary();
        return reporter.ExitCode;
    }

    private static int Watch(IDetectionSink sink, Reporter reporter, AmsiScanner? amsi)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        new WatchService(sink, amsi).Run(cts.Token);
        reporter.Summary();
        return reporter.ExitCode;
    }

    private static int Monitor(IDetectionSink sink, Reporter reporter, AmsiScanner? amsi)
    {
        if (!EtwSensor.IsElevated())
            reporter.Info("monitor: ETW requires Administrator — run elevated for live telemetry.");
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        using var sensor = new EtwSensor(sink, amsi);
        sensor.Run(cts.Token);
        reporter.Summary();
        return reporter.ExitCode;
    }

    private static int SelfTest(IDetectionSink sink, Reporter reporter, AmsiScanner? amsi)
    {
        reporter.Info("selftest: verifying AMSI + heuristic pipeline (uses harmless test artifacts).");

        // 1) Official AMSI test string — a working AMSI provider MUST flag it.
        const string amsiTest = "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386";
        bool amsiDetected = false;
        if (amsi is not null)
        {
            var amsiResult = amsi.ScanString(amsiTest, "selftest:amsi", "selftest");
            amsiDetected = amsiResult.Verdict == Verdict.Malicious;
            sink.Report(amsiResult);
        }
        else
            reporter.Info("selftest: AMSI disabled/unavailable — skipping AMSI checks.");

        // 2) EICAR test signature, scanned in-memory (no disk write, so on-access
        //    AV cannot interfere with the test).
        var eicar = System.Text.Encoding.ASCII.GetBytes(ContentHeuristics.EicarSignature);
        if (ContentHeuristics.LooksLikeEicar(eicar))
            sink.Report(new Detection("Heuristics", "selftest:eicar", Severity.High, Verdict.Malicious,
                "heuristic.eicar", "EICAR test signature detected by heuristic engine."));
        if (amsi is not null)
            sink.Report(amsi.Scan(eicar, "selftest:eicar", "eicar.txt"));

        reporter.Summary();
        // AMSI is "proven" only if it actually DETECTED the sample (not merely
        // errored). When no provider is present we can't prove it here.
        bool amsiProven = amsi is null || amsiDetected;
        if (amsi is null)
            reporter.Info("selftest: heuristic pipeline OK (AMSI not testable — no provider).");
        else
            reporter.Info(amsiProven
                ? "selftest: OK — AMSI + heuristic pipeline is working."
                : "selftest: WARNING — AMSI did not detect the test sample (provider disabled or errored).");
        return reporter.ExitCode;
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
"""
Detector — a small defensive antivirus (AMSI + RunPE + PowerShell).

Usage:
  detector <command> [args] [options]

Commands:
  analyze <path>       Build a correlated case for a file or source directory.
  import-trace <path>  Import JSONL runtime evidence from a VM or sandbox.
  scan-file <path>     Scan a file with AMSI + heuristics (EICAR, entropy).
  scan-dir  <path>     Recursively scan a directory.
  scan-ps   <path|->   Scan a PowerShell script/command (deobfuscate + AMSI).
  scan-proc <pid|all>  Scan process memory for RunPE / hollowing / injection.
  watch                Poll for new processes + PowerShell launches (no admin).
  monitor              ETW real-time sensor: process/DLL/PowerShell telemetry
                       fed into the engine (needs Administrator).
  selftest             Prove the AMSI + heuristic pipeline works (safe samples).

Options:
  --report-json <path> Write the complete case as deterministic JSON.
  --report-html <path> Write a self-contained, encoded HTML case report.
  --json <path>        Append findings as JSON lines to <path>.
  --verbose, -v        Show clean results + the filtered/telemetry trace stream.
  -vv, --debug         Even more: every raw event (process/DLL/dedup) is traced.
  --no-filter          Disable false-positive filtering (show everything raw).
  --no-amsi            Disable AMSI; use heuristics only.
  --aggressive         scan-proc: also flag any unbacked executable memory
                       (noisy — legitimate JIT/thunks will match).

Notes:
  * scan-proc / watch may require running elevated (Administrator) to read
    other processes' memory.
  * This tool is read-only and defensive: it never injects, modifies, quarantines
    or deletes anything.

Exit codes: 0 clean, 1 suspicious, 2 malicious, 3 error.
""");
    }
}
