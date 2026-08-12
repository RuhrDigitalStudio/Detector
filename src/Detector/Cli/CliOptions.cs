using Detector.Reporting;

namespace Detector.Cli;

/// Parses global flags while preserving command-specific positional arguments.
public sealed class CliOptions
{
    public string? Command { get; private set; }
    public List<string> Positional { get; } = new();
    public string? JsonPath { get; private set; }
    public TraceLevel Verbosity { get; private set; } = TraceLevel.Normal;
    public bool NoAmsi { get; private set; }
    public bool Aggressive { get; private set; }
    public bool NoFilter { get; private set; }

    /// True when either verbose mode was requested.
    public bool Verbose => Verbosity >= TraceLevel.Verbose;

    /// Contains a message when parsing fails, such as a flag without its operand.
    public string? Error { get; private set; }

    public static CliOptions Parse(string[] args)
    {
        var o = new CliOptions();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "--json":
                    // Reject a missing or flag-like path instead of consuming the
                    // next option and silently losing the requested log output.
                    if (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                        o.JsonPath = args[++i];
                    else
                        o.Error = "--json requires a <path> argument";
                    break;
                case "--verbose":
                case "-v":
                    if (o.Verbosity < TraceLevel.Verbose) o.Verbosity = TraceLevel.Verbose;
                    break;
                case "-vv":
                case "--debug":
                case "--trace":
                    o.Verbosity = TraceLevel.Debug;
                    break;
                case "--no-amsi":
                    o.NoAmsi = true;
                    break;
                case "--aggressive":
                    o.Aggressive = true;
                    break;
                case "--no-filter":
                    o.NoFilter = true;
                    break;
                default:
                    if (o.Command is null) o.Command = a;
                    else o.Positional.Add(a);
                    break;
            }
        }
        return o;
    }
}
