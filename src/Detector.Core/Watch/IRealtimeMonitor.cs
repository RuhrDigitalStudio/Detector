namespace Detector.Watch;

/// A real-time monitor that runs until its cancellation token fires. Implemented
/// by the polling WatchService and the ETW-based EtwSensor, so front-ends can
/// pick whichever is available.
public interface IRealtimeMonitor
{
    void Run(CancellationToken token);
}
