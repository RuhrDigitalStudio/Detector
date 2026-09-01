using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace Detector.Gui;

public partial class App : Application
{
    public App()
    {
        // Software rendering is useful in remote analysis VMs where the WPF GPU
        // pipeline may be unavailable. Local desktops keep hardware acceleration.
        if (Environment.GetEnvironmentVariable("DETECTOR_SOFTWARE_RENDERING") == "1")
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
    }
}
