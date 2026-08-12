using Xunit;

namespace ArtifactSigning.Windows.Tests;

public sealed class MicrosoftArtifactSigningPolicyTests
{
    private const string Sha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public void AcceptsClosedJapanEastPolicy()
    {
        MicrosoftArtifactSigningPolicy policy = CreatePolicy();

        Assert.Equal(MicrosoftArtifactSigningRegion.JapanEast, policy.Region);
        Assert.Equal("https://jpe.codesigning.azure.net/", policy.Endpoint.AbsoluteUri);
        Assert.Equal("example-signing-account", policy.CodeSigningAccountName);
        Assert.Equal("Example-PublicTrust", policy.CertificateProfileName);
        Assert.Equal(GetSignToolPath(), policy.SignToolAbsolutePath);
        Assert.Equal(GetDlibPath(), policy.DlibAbsolutePath);
        Assert.Equal(new Version(10, 0, 26100, 4188), policy.SignToolFileVersion);
        Assert.Equal(new Version(1, 2, 3, 4), policy.DlibFileVersion);
        Assert.Equal(Sha256, policy.ClientToolsInventorySha256);
        Assert.Equal(
            MicrosoftArtifactSigningPolicy.MicrosoftTimestampUrl,
            policy.TimestampUrl.AbsoluteUri);
        Assert.Equal(TimeSpan.FromSeconds(120), policy.Timeout);
        Assert.Same(AzureArcManagedIdentityEnvironment.Default, policy.AzureArcEnvironment);
    }

    [Theory]
    [InlineData(MicrosoftArtifactSigningRegion.BrazilSouth, "brs")]
    [InlineData(MicrosoftArtifactSigningRegion.CentralUS, "cus")]
    [InlineData(MicrosoftArtifactSigningRegion.EastUS, "eus")]
    [InlineData(MicrosoftArtifactSigningRegion.JapanEast, "jpe")]
    [InlineData(MicrosoftArtifactSigningRegion.KoreaCentral, "krc")]
    [InlineData(MicrosoftArtifactSigningRegion.NorthCentralUS, "ncus")]
    [InlineData(MicrosoftArtifactSigningRegion.NorthEurope, "neu")]
    [InlineData(MicrosoftArtifactSigningRegion.PolandCentral, "plc")]
    [InlineData(MicrosoftArtifactSigningRegion.SouthCentralUS, "scus")]
    [InlineData(MicrosoftArtifactSigningRegion.SwitzerlandNorth, "swn")]
    [InlineData(MicrosoftArtifactSigningRegion.WestCentralUS, "wcus")]
    [InlineData(MicrosoftArtifactSigningRegion.WestEurope, "weu")]
    [InlineData(MicrosoftArtifactSigningRegion.WestUS, "wus")]
    [InlineData(MicrosoftArtifactSigningRegion.WestUS2, "wus2")]
    [InlineData(MicrosoftArtifactSigningRegion.WestUS3, "wus3")]
    public void AcceptsDocumentedRegion(
        MicrosoftArtifactSigningRegion region,
        string endpointPrefix)
    {
        MicrosoftArtifactSigningPolicy policy = CreatePolicy(region: region);

        Assert.Equal(
            $"https://{endpointPrefix}.codesigning.azure.net/",
            policy.Endpoint.AbsoluteUri);
    }

    [Theory]
    [InlineData("not--safe")]
    [InlineData("ExampleArtifactSigning")]
    [InlineData("ab")]
    [InlineData("1exampleartifactsigning")]
    [InlineData("-exampleartifactsigning")]
    [InlineData("exampleartifactsigning-")]
    [InlineData("oneartifactsigning")]
    [InlineData("example_artifact_signing")]
    public void RejectsUnsafeAccountName(string accountName)
    {
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(codeSigningAccountName: accountName));
    }

    [Theory]
    [InlineData("ab")]
    [InlineData("1ExamplePublicTrust")]
    [InlineData("Example PublicTrust")]
    [InlineData("Example_PublicTrust")]
    [InlineData("-ExamplePublicTrust")]
    [InlineData("Example--PublicTrust")]
    public void RejectsUnsafeCertificateProfileName(string profileName)
    {
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(certificateProfileName: profileName));
    }

    [Theory]
    [InlineData("signtool.exe")]
    [InlineData("/opt/tools/not-signtool.exe")]
    [InlineData(@"C:\Tools\..\signtool.exe")]
    [InlineData(@"C:\Tools\\signtool.exe")]
    [InlineData(@"C:\Tools.\signtool.exe")]
    [InlineData(@"C:\CON\signtool.exe")]
    [InlineData(@"C:\Tools:stream\signtool.exe")]
    public void RejectsUnsafeSignToolPath(string path)
    {
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(signToolAbsolutePath: path));
    }

    [Theory]
    [InlineData("Azure.CodeSigning.Dlib.dll")]
    [InlineData("/opt/tools/not-dlib.dll")]
    [InlineData(@"C:\Tools\..\Azure.CodeSigning.Dlib.dll")]
    [InlineData(@"C:\Tools\\Azure.CodeSigning.Dlib.dll")]
    [InlineData(@"C:\NUL\Azure.CodeSigning.Dlib.dll")]
    public void RejectsUnsafeDlibPath(string path)
    {
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(dlibAbsolutePath: path));
    }

    [Fact]
    public void RejectsUnknownRegion()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => CreatePolicy(region: (MicrosoftArtifactSigningRegion)999));
    }

    [Theory]
    [InlineData("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("0123456789abcdef")]
    public void RejectsNoncanonicalDigest(string value)
    {
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(signToolSha256: value));
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(dlibSha256: value));
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(clientToolsInventorySha256: value));
    }

    [Fact]
    public void RejectsShortComponentVersion()
    {
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(signToolFileVersion: new Version(10, 0)));
        Assert.Throws<ArgumentException>(
            () => CreatePolicy(dlibFileVersion: new Version(1, 2)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(121)]
    public void RejectsTimeoutOutsideClosedRange(int seconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => CreatePolicy(timeout: TimeSpan.FromSeconds(seconds)));
    }

    [Theory]
    [InlineData("http://localhost:40342/metadata/identity/oauth2/not-token", "http://localhost:40342/")]
    [InlineData("https://localhost:40342/metadata/identity/oauth2/token", "http://localhost:40342")]
    [InlineData("http://127.0.0.1:40342/metadata/identity/oauth2/token", "http://localhost:40342")]
    [InlineData("http://localhost:40342/metadata/identity/oauth2/token", "http://localhost:40342/")]
    public void RejectsNoncanonicalArcEnvironment(
        string identityEndpoint,
        string imdsEndpoint)
    {
        Assert.Throws<ArgumentException>(
            () => new AzureArcManagedIdentityEnvironment(
                new Uri(identityEndpoint),
                new Uri(imdsEndpoint)));
    }

    private static MicrosoftArtifactSigningPolicy CreatePolicy(
        MicrosoftArtifactSigningRegion region = MicrosoftArtifactSigningRegion.JapanEast,
        string codeSigningAccountName = "example-signing-account",
        string certificateProfileName = "Example-PublicTrust",
        string? signToolAbsolutePath = null,
        string signToolSha256 = Sha256,
        Version? signToolFileVersion = null,
        string? dlibAbsolutePath = null,
        string dlibSha256 = Sha256,
        Version? dlibFileVersion = null,
        string clientToolsInventorySha256 = Sha256,
        TimeSpan? timeout = null)
    {
        return new MicrosoftArtifactSigningPolicy(
            region,
            codeSigningAccountName,
            certificateProfileName,
            signToolAbsolutePath ?? GetSignToolPath(),
            signToolSha256,
            signToolFileVersion ?? new Version(10, 0, 26100, 4188),
            dlibAbsolutePath ?? GetDlibPath(),
            dlibSha256,
            dlibFileVersion ?? new Version(1, 2, 3, 4),
            clientToolsInventorySha256,
            timeout ?? TimeSpan.FromSeconds(120));
    }

    internal static string GetSignToolPath()
    {
        return @"C:\Program Files (x86)\Windows Kits\10\bin\signtool.exe";
    }

    internal static string GetDlibPath()
    {
        return @"C:\Program Files\ArtifactSigning\Tools\Azure.CodeSigning.Dlib.dll";
    }
}
