using Detector.Analysis;
using Detector.Model;

namespace Detector.Tests;

public sealed class SourceAnalyzerTests
{
    [Fact]
    public void AnalyzeCSharp_ReportsInteropAndProcessModificationPrimitives()
    {
        const string source = """
            using System;
            using System.Runtime.InteropServices;
            internal static class Native
            {
                [DllImport("kernel32.dll")] internal static extern IntPtr OpenProcess(int access, bool inherit, int pid);
                [DllImport("kernel32.dll")] internal static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, int size, int type, int protect);
                [DllImport("kernel32.dll")] internal static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] data, int size, out int written);
                [DllImport("kernel32.dll")] internal static extern IntPtr CreateRemoteThread(IntPtr process, IntPtr attrs, int stack, IntPtr start, IntPtr parameter, int flags, out int id);
            }
            """;

        var findings = SourceAnalyzer.AnalyzeCSharp(source, "Synthetic.cs");

        Assert.Contains(findings, item => item.Rule == "source.cs.pinvoke");
        Assert.Contains(findings, item => item.Rule == "source.cs.open-process");
        Assert.Contains(findings, item => item.Rule == "source.cs.memory-allocation");
        Assert.Contains(findings, item => item.Rule == "source.cs.process-memory-write");
        Assert.Contains(findings, item => item.Rule == "source.cs.remote-thread");
        Assert.All(findings, item => Assert.NotEqual(Verdict.Malicious, item.Verdict));
    }

    [Fact]
    public void AnalyzeCSharp_DoesNotFlagOrdinaryConsoleProgram()
    {
        const string source = """
            using System;
            internal static class Program
            {
                public static void Main() => Console.WriteLine("Hello from a normal tool");
            }
            """;

        Assert.Empty(SourceAnalyzer.AnalyzeCSharp(source, "Program.cs"));
    }

    [Fact]
    public void AnalyzeCSharp_IncludesBoundedLineEvidence()
    {
        const string source = "using System.Reflection;\nclass Loader { void Go(byte[] value) => Assembly.Load(value); }";

        var finding = Assert.Single(SourceAnalyzer.AnalyzeCSharp(source, "Loader.cs"));

        Assert.Equal("source.cs.dynamic-load", finding.Rule);
        Assert.Contains("line 2", finding.Details, StringComparison.OrdinalIgnoreCase);
        Assert.True(finding.Details.Length < 300);
    }
}
