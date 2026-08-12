using System.Text;
using Detector.Heuristics;
using Xunit;

public class HeuristicsTests
{
    [Fact]
    public void HighEntropy_For_Uniform_Byte_Spread()
    {
        var data = new byte[4096];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i * 131 + 7); // hits all 256 values evenly
        Assert.True(ContentHeuristics.ShannonEntropy(data) > 7.0);
    }

    [Fact]
    public void LowEntropy_For_Repeated_Byte()
    {
        Assert.True(ContentHeuristics.ShannonEntropy(new byte[1000]) < 1.0);
    }

    [Fact]
    public void Entropy_Of_Empty_Is_Zero()
    {
        Assert.Equal(0, ContentHeuristics.ShannonEntropy(Array.Empty<byte>()));
    }

    [Fact]
    public void Detects_Eicar_Signature()
    {
        var eicar = Encoding.ASCII.GetBytes(ContentHeuristics.EicarSignature);
        Assert.True(ContentHeuristics.LooksLikeEicar(eicar));
    }

    [Fact]
    public void Eicar_Detected_When_Embedded()
    {
        var buf = Encoding.ASCII.GetBytes("junk-prefix " + ContentHeuristics.EicarSignature + " junk-suffix");
        Assert.True(ContentHeuristics.LooksLikeEicar(buf));
    }

    [Fact]
    public void No_Eicar_In_Clean_Data()
    {
        Assert.False(ContentHeuristics.LooksLikeEicar(Encoding.ASCII.GetBytes("hello world")));
    }
}
