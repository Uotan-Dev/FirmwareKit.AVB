namespace FirmwareKit.AVB.Tests;

public class AvbVersionTests
{
    [Fact]
    public void VersionConstants_ShouldMatchLibavbVersion()
    {
        Assert.Equal(1u, AvbVersion.Major);
        Assert.Equal(3u, AvbVersion.Minor);
        Assert.Equal(0u, AvbVersion.Sub);
        Assert.Equal("1.3.0", AvbVersion.VersionString);
    }

    [Fact]
    public void IsCompatible_ShouldRequireSameMajorAndSupportedMinor()
    {
        Assert.True(AvbVersion.IsCompatible(1, 0));
        Assert.True(AvbVersion.IsCompatible(1, 3));
        Assert.False(AvbVersion.IsCompatible(1, 4));
        Assert.False(AvbVersion.IsCompatible(2, 0));
    }
}
