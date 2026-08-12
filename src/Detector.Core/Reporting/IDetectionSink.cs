using Detector.Model;

namespace Detector.Reporting;

/// How much low-level telemetry to surface. Detections are always shown; traces
/// are the raw "advanced" stream (every event, filtered items, debug detail).
public enum TraceLevel { Normal = 0, Verbose = 1, Debug = 2 }

/// A destination for scan findings and status messages. Implemented by the
/// console Reporter and by the GUI (which appends to its results list). This is
/// what decouples scanners/watch from any particular front-end.
public interface IDetectionSink
{
    void Report(Detection detection);
    void Info(string message);

    /// Low-level telemetry, shown only when the front-end's verbosity is at or
    /// above <paramref name="level"/>. Used for the advanced/raw event stream and
    /// for reporting items the false-positive filter suppressed.
    void Trace(TraceLevel level, string message);
}
