using Detector.PowerShell;
using Xunit;

public class ScriptBlockAssemblerTests
{
    [Fact]
    public void Single_Part_Returns_Immediately()
    {
        var a = new ScriptBlockAssembler();
        Assert.Equal("hello", a.Add("id1", 1, 1, "hello"));
    }

    [Fact]
    public void Multi_Part_In_Order_Reassembles()
    {
        var a = new ScriptBlockAssembler();
        Assert.Null(a.Add("id2", 1, 3, "aaa"));
        Assert.Null(a.Add("id2", 2, 3, "bbb"));
        Assert.Equal("aaabbbccc", a.Add("id2", 3, 3, "ccc"));
    }

    [Fact]
    public void Multi_Part_Out_Of_Order_Reassembles()
    {
        var a = new ScriptBlockAssembler();
        Assert.Null(a.Add("id3", 3, 3, "ccc"));
        Assert.Null(a.Add("id3", 1, 3, "aaa"));
        Assert.Equal("aaabbbccc", a.Add("id3", 2, 3, "bbb"));
    }

    [Fact]
    public void Completed_Block_Is_Deduplicated()
    {
        var a = new ScriptBlockAssembler();
        Assert.Equal("x", a.Add("id4", 1, 1, "x"));
        Assert.Null(a.Add("id4", 1, 1, "x")); // same id again -> ignored
    }

    [Fact]
    public void No_Id_With_Multiple_Parts_Cannot_Correlate()
    {
        var a = new ScriptBlockAssembler();
        Assert.Null(a.Add("", 1, 3, "aaa"));
    }
}
