using Detector.Process;
using Xunit;

public class PeAnalyzerTests
{
    private static byte[] MinimalPe()
    {
        var buf = new byte[0x100];
        buf[0] = (byte)'M'; buf[1] = (byte)'Z';
        int lfanew = 0x80;
        BitConverter.GetBytes(lfanew).CopyTo(buf, 0x3C);
        buf[lfanew] = (byte)'P'; buf[lfanew + 1] = (byte)'E';
        buf[lfanew + 2] = 0; buf[lfanew + 3] = 0;
        return buf;
    }

    [Fact] public void Detects_Pe_Header() => Assert.True(PeAnalyzer.HasPeHeader(MinimalPe()));
    [Fact] public void Rejects_NonPe() => Assert.False(PeAnalyzer.HasPeHeader(new byte[0x100]));
    [Fact] public void Rejects_Truncated_Mz() => Assert.False(PeAnalyzer.HasPeHeader(new byte[] { (byte)'M', (byte)'Z' }));

    [Fact]
    public void Rejects_Pe_With_Out_Of_Range_Lfanew()
    {
        var buf = new byte[0x100];
        buf[0] = (byte)'M'; buf[1] = (byte)'Z';
        BitConverter.GetBytes(0x7FFFFFFF).CopyTo(buf, 0x3C);
        Assert.False(PeAnalyzer.HasPeHeader(buf));
    }

    [Fact]
    public void Classifies_Private_Exec_Pe_As_RunPe()
    {
        var v = PeAnalyzer.Classify(isPrivate: true, isImage: false, isExecutable: true, hasPe: true, isRwx: false);
        Assert.Equal("runpe.unbacked-exec-pe", v.rule);
        Assert.True((int)v.severity >= 3);
    }

    [Fact]
    public void Private_Rwx_Silent_By_Default()
    {
        var v = PeAnalyzer.Classify(isPrivate: true, isImage: false, isExecutable: true, hasPe: false, isRwx: true);
        Assert.Null(v.rule);
    }

    [Fact]
    public void Private_Rwx_Flagged_When_Aggressive()
    {
        var v = PeAnalyzer.Classify(isPrivate: true, isImage: false, isExecutable: true, hasPe: false, isRwx: true, aggressive: true);
        Assert.Equal("runpe.private-rwx", v.rule);
        Assert.Equal(Detector.Model.Severity.High, v.severity);
    }

    [Fact]
    public void Unbacked_Exec_Without_Pe_Silent_By_Default()
    {
        var v = PeAnalyzer.Classify(isPrivate: false, isImage: false, isExecutable: true, hasPe: false, isRwx: false);
        Assert.Null(v.rule);
    }

    [Fact]
    public void Unbacked_Exec_Without_Pe_Flagged_When_Aggressive()
    {
        var v = PeAnalyzer.Classify(isPrivate: false, isImage: false, isExecutable: true, hasPe: false, isRwx: false, aggressive: true);
        Assert.Equal("runpe.unbacked-exec", v.rule);
        Assert.Equal(Detector.Model.Severity.Low, v.severity);
    }

    [Fact]
    public void Real_RunPe_Flagged_Even_Without_Aggressive()
    {
        var v = PeAnalyzer.Classify(isPrivate: true, isImage: false, isExecutable: true, hasPe: true, isRwx: false, aggressive: false);
        Assert.Equal("runpe.unbacked-exec-pe", v.rule);
    }

    [Fact]
    public void Clean_Image_Region_Not_Flagged()
    {
        var v = PeAnalyzer.Classify(isPrivate: false, isImage: true, isExecutable: true, hasPe: true, isRwx: false);
        Assert.Null(v.rule);
    }

    [Fact]
    public void NonExecutable_Region_Not_Flagged()
    {
        var v = PeAnalyzer.Classify(isPrivate: true, isImage: false, isExecutable: false, hasPe: false, isRwx: false);
        Assert.Null(v.rule);
    }
}
