using Detector.Analysis;
using Detector.Model;

namespace Detector.Tests;

public sealed class AnalysisServiceTests
{
    [Fact]
    public void AnalyzePath_BuildsCorrelatedCaseFromCSharpSource()
    {
        var root = CreateDirectory();
        try
        {
            var path = Path.Combine(root, "Interop.cs");
            File.WriteAllText(path, """
                using System;
                class Interop {
                  void Go() {
                    OpenProcess(1, false, 4); VirtualAllocEx(IntPtr.Zero, IntPtr.Zero, 1, 1, 1);
                    WriteProcessMemory(IntPtr.Zero, IntPtr.Zero, new byte[1], 1, out _);
                    CreateRemoteThread(IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, 0, out _);
                  }
                }
                """);

            var report = new AnalysisService(amsi: null).AnalyzePath(path, "Synthetic source");

            Assert.Single(report.Artifacts);
            Assert.Equal(ArtifactKind.CSharpSource, report.Artifacts[0].Kind);
            Assert.Contains(report.Capabilities, item =>
                item.Id == "capability.process-injection" && item.Confidence == Confidence.High);
            Assert.Equal(Verdict.Suspicious, report.Assessment.Verdict);
            Assert.Contains(report.Coverage, item => item.Module == "AMSI" && item.State == CoverageState.Unavailable);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void AnalyzePath_EnumeratesDirectoryAndSortsArtifacts()
    {
        var root = CreateDirectory();
        try
        {
            File.WriteAllText(Path.Combine(root, "z.txt"), "last");
            File.WriteAllText(Path.Combine(root, "a.txt"), "first");

            var report = new AnalysisService(null).AnalyzePath(root, "Directory case");

            Assert.Equal(["a.txt", "z.txt"], report.Artifacts.Select(item => item.DisplayName));
            Assert.Contains(report.Coverage, item => item.Module == "Input enumeration" && item.State == CoverageState.Completed);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void ImportRuntimeTrace_CorrelatesRemoteProcessSequence()
    {
        var root = CreateDirectory();
        try
        {
            var path = Path.Combine(root, "trace.jsonl");
            File.WriteAllText(path, """
                {"ProviderName":"Microsoft-Windows-Sysmon","EventID":10,"SourceProcessId":"10","GrantedAccess":"0x0020"}
                {"ProviderName":"Microsoft-Windows-Sysmon","EventID":8,"SourceProcessId":"10","TargetProcessId":"20"}
                """);

            var report = new AnalysisService(null).ImportRuntimeTrace(path, "Runtime case");

            Assert.Equal(2, report.Timeline.Count);
            Assert.Contains(report.Capabilities, item =>
                item.Id == "capability.process-injection" && item.Confidence == Confidence.Medium);
            Assert.Equal(Verdict.Suspicious, report.Assessment.Verdict);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void AnalyzePath_ReturnsExplainableErrorCaseForMissingInput()
    {
        var report = new AnalysisService(null).AnalyzePath("missing-artifact.bin", "Missing");

        Assert.Equal(Verdict.Error, report.Assessment.Verdict);
        Assert.Contains(report.Findings, item => item.Rule == "analysis.input-not-found");
        Assert.True(report.HasCoverageGaps);
    }

    private static string CreateDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "DetectorTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
