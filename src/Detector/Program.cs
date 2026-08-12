using System.Text;
using Detector.Cli;

// Make sure non-ASCII detail text renders correctly regardless of the console
// code page. Ignore failures (e.g. when output is redirected).
try { Console.OutputEncoding = Encoding.UTF8; } catch { /* not critical */ }

return CommandRouter.Run(args);
