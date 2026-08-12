using Xunit;

namespace ArtifactSigning.Profiles.Tests;

public sealed class SigningProfileIdentityTests
{
    [Fact]
    public void ConstructorPreservesValidIdentity()
    {
        var identity = new SigningProfileIdentity("ExampleProfileV1", 1);

        Assert.Equal("ExampleProfileV1", identity.ProfileId);
        Assert.Equal(1, identity.ProfileVersion);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("../Example")]
    [InlineData("Example/Profile")]
    public void ConstructorRejectsInvalidProfileId(string profileId)
    {
        Assert.Throws<ArgumentException>(() => new SigningProfileIdentity(profileId, 1));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    public void ConstructorRejectsNonPositiveVersion(int profileVersion)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new SigningProfileIdentity("ExampleProfileV1", profileVersion));
    }
}
