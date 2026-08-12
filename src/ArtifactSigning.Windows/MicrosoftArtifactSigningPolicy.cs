namespace ArtifactSigning.Windows;

public enum MicrosoftArtifactSigningRegion
{
    BrazilSouth,
    CentralUS,
    EastUS,
    JapanEast,
    KoreaCentral,
    NorthCentralUS,
    NorthEurope,
    PolandCentral,
    SouthCentralUS,
    SwitzerlandNorth,
    WestCentralUS,
    WestEurope,
    WestUS,
    WestUS2,
    WestUS3,
}

public sealed class MicrosoftArtifactSigningPolicy
{
    public const string MicrosoftTimestampUrl = "http://timestamp.acs.microsoft.com/";
    public const int MaximumAccountNameCharacters = 24;
    public const int MaximumCertificateProfileNameCharacters = 100;
    public static readonly TimeSpan MaximumTimeout = TimeSpan.FromSeconds(120);

    public MicrosoftArtifactSigningPolicy(
        MicrosoftArtifactSigningRegion region,
        string codeSigningAccountName,
        string certificateProfileName,
        string signToolAbsolutePath,
        string signToolSha256,
        Version signToolFileVersion,
        string dlibAbsolutePath,
        string dlibSha256,
        Version dlibFileVersion,
        string clientToolsInventorySha256,
        TimeSpan timeout,
        AzureArcManagedIdentityEnvironment? azureArcEnvironment = null)
    {
        ArgumentNullException.ThrowIfNull(codeSigningAccountName);
        ArgumentNullException.ThrowIfNull(certificateProfileName);
        ArgumentNullException.ThrowIfNull(signToolAbsolutePath);
        ArgumentNullException.ThrowIfNull(signToolSha256);
        ArgumentNullException.ThrowIfNull(signToolFileVersion);
        ArgumentNullException.ThrowIfNull(dlibAbsolutePath);
        ArgumentNullException.ThrowIfNull(dlibSha256);
        ArgumentNullException.ThrowIfNull(dlibFileVersion);
        ArgumentNullException.ThrowIfNull(clientToolsInventorySha256);

        Endpoint = GetEndpoint(region);
        Region = region;

        if (!IsSafeAccountName(codeSigningAccountName))
        {
            throw new ArgumentException(
                "Code-signing account name is not a safe installed value.",
                nameof(codeSigningAccountName));
        }

        if (!IsSafeCertificateProfileName(certificateProfileName))
        {
            throw new ArgumentException(
                "Certificate profile name is not a safe installed value.",
                nameof(certificateProfileName));
        }

        if (!WindowsContractRules.IsAbsoluteLeafPath(
                signToolAbsolutePath,
                "signtool.exe"))
        {
            throw new ArgumentException(
                "SignTool path must be absolute and end with signtool.exe.",
                nameof(signToolAbsolutePath));
        }

        if (!WindowsContractRules.IsLowerSha256(signToolSha256))
        {
            throw new ArgumentException(
                "SignTool digest must be canonical lowercase SHA-256.",
                nameof(signToolSha256));
        }

        if (!HasFourPartVersion(signToolFileVersion))
        {
            throw new ArgumentException(
                "SignTool version must contain four nonnegative components.",
                nameof(signToolFileVersion));
        }

        if (!WindowsContractRules.IsAbsoluteLeafPath(
                dlibAbsolutePath,
                "Azure.CodeSigning.Dlib.dll"))
        {
            throw new ArgumentException(
                "Artifact Signing Dlib path must be absolute and end with Azure.CodeSigning.Dlib.dll.",
                nameof(dlibAbsolutePath));
        }

        if (!WindowsContractRules.IsLowerSha256(dlibSha256))
        {
            throw new ArgumentException(
                "Artifact Signing Dlib digest must be canonical lowercase SHA-256.",
                nameof(dlibSha256));
        }

        if (!HasFourPartVersion(dlibFileVersion))
        {
            throw new ArgumentException(
                "Artifact Signing Dlib version must contain four nonnegative components.",
                nameof(dlibFileVersion));
        }

        if (!WindowsContractRules.IsLowerSha256(clientToolsInventorySha256))
        {
            throw new ArgumentException(
                "Artifact Signing client-tools inventory digest must be canonical lowercase SHA-256.",
                nameof(clientToolsInventorySha256));
        }

        if (timeout < TimeSpan.FromSeconds(1) || timeout > MaximumTimeout)
        {
            throw new ArgumentOutOfRangeException(
                nameof(timeout),
                "Artifact Signing timeout must be from one through 120 seconds.");
        }

        CodeSigningAccountName = codeSigningAccountName;
        CertificateProfileName = certificateProfileName;
        SignToolAbsolutePath = signToolAbsolutePath;
        SignToolSha256 = signToolSha256;
        SignToolFileVersion = CopyVersion(signToolFileVersion);
        DlibAbsolutePath = dlibAbsolutePath;
        DlibSha256 = dlibSha256;
        DlibFileVersion = CopyVersion(dlibFileVersion);
        ClientToolsInventorySha256 = clientToolsInventorySha256;
        TimestampUrl = new Uri(MicrosoftTimestampUrl, UriKind.Absolute);
        Timeout = timeout;
        AzureArcEnvironment = azureArcEnvironment
            ?? AzureArcManagedIdentityEnvironment.Default;
    }

    public MicrosoftArtifactSigningRegion Region { get; }

    public Uri Endpoint { get; }

    public string CodeSigningAccountName { get; }

    public string CertificateProfileName { get; }

    public string SignToolAbsolutePath { get; }

    public string SignToolSha256 { get; }

    public Version SignToolFileVersion { get; }

    public string DlibAbsolutePath { get; }

    public string DlibSha256 { get; }

    public Version DlibFileVersion { get; }

    public string ClientToolsInventorySha256 { get; }

    public Uri TimestampUrl { get; }

    public TimeSpan Timeout { get; }

    public AzureArcManagedIdentityEnvironment AzureArcEnvironment { get; }

    private static Uri GetEndpoint(MicrosoftArtifactSigningRegion region)
    {
        return region switch
        {
            MicrosoftArtifactSigningRegion.BrazilSouth =>
                new Uri("https://brs.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.CentralUS =>
                new Uri("https://cus.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.EastUS =>
                new Uri("https://eus.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.JapanEast =>
                new Uri("https://jpe.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.KoreaCentral =>
                new Uri("https://krc.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.NorthCentralUS =>
                new Uri("https://ncus.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.NorthEurope =>
                new Uri("https://neu.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.PolandCentral =>
                new Uri("https://plc.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.SouthCentralUS =>
                new Uri("https://scus.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.SwitzerlandNorth =>
                new Uri("https://swn.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.WestCentralUS =>
                new Uri("https://wcus.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.WestEurope =>
                new Uri("https://weu.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.WestUS =>
                new Uri("https://wus.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.WestUS2 =>
                new Uri("https://wus2.codesigning.azure.net", UriKind.Absolute),
            MicrosoftArtifactSigningRegion.WestUS3 =>
                new Uri("https://wus3.codesigning.azure.net", UriKind.Absolute),
            _ => throw new ArgumentOutOfRangeException(
                nameof(region),
                "Artifact Signing region is not supported by installed policy."),
        };
    }

    private static bool IsSafeAccountName(string value)
    {
        return IsSafeAsciiIdentifier(
                value,
                minimumLength: 3,
                maximumLength: MaximumAccountNameCharacters,
                allowHyphen: true,
                requireLowercase: true)
            && !value.StartsWith("one", StringComparison.Ordinal);
    }

    private static bool IsSafeCertificateProfileName(string value)
    {
        return IsSafeAsciiIdentifier(
            value,
            minimumLength: 5,
            maximumLength: MaximumCertificateProfileNameCharacters,
            allowHyphen: true,
            requireLowercase: false);
    }

    private static bool IsSafeAsciiIdentifier(
        string value,
        int minimumLength,
        int maximumLength,
        bool allowHyphen,
        bool requireLowercase)
    {
        if (value.Length < minimumLength
            || value.Length > maximumLength
            || !char.IsAsciiLetter(value[0])
            || !char.IsAsciiLetterOrDigit(value[^1]))
        {
            return false;
        }

        bool previousWasHyphen = false;
        foreach (char character in value)
        {
            if (char.IsAsciiDigit(character)
                || (character is >= 'a' and <= 'z')
                || (!requireLowercase && character is >= 'A' and <= 'Z'))
            {
                previousWasHyphen = false;
                continue;
            }

            if (allowHyphen && character == '-' && !previousWasHyphen)
            {
                previousWasHyphen = true;
                continue;
            }

            return false;
        }

        return true;
    }

    private static bool HasFourPartVersion(Version version)
    {
        return version.Major >= 0
            && version.Minor >= 0
            && version.Build >= 0
            && version.Revision >= 0;
    }

    private static Version CopyVersion(Version version)
    {
        return new Version(
            version.Major,
            version.Minor,
            version.Build,
            version.Revision);
    }
}

public sealed class AzureArcManagedIdentityEnvironment
{
    public const string IdentityEndpointEnvironmentVariable = "IDENTITY_ENDPOINT";
    public const string ImdsEndpointEnvironmentVariable = "IMDS_ENDPOINT";
    public const string IdentityEndpointValue =
        "http://localhost:40342/metadata/identity/oauth2/token";
    public const string ImdsEndpointValue = "http://localhost:40342";

    public static AzureArcManagedIdentityEnvironment Default { get; } = new(
        new Uri(IdentityEndpointValue, UriKind.Absolute),
        new Uri(ImdsEndpointValue, UriKind.Absolute));

    public AzureArcManagedIdentityEnvironment(
        Uri identityEndpoint,
        Uri imdsEndpoint)
    {
        ArgumentNullException.ThrowIfNull(identityEndpoint);
        ArgumentNullException.ThrowIfNull(imdsEndpoint);
        if (!string.Equals(
                identityEndpoint.OriginalString,
                IdentityEndpointValue,
                StringComparison.Ordinal)
            || !string.Equals(
                imdsEndpoint.OriginalString,
                ImdsEndpointValue,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Azure Arc managed-identity endpoints must use the installed loopback endpoints.");
        }

        IdentityEndpoint = new Uri(identityEndpoint.OriginalString, UriKind.Absolute);
        ImdsEndpoint = new Uri(imdsEndpoint.OriginalString, UriKind.Absolute);
    }

    public Uri IdentityEndpoint { get; }

    public Uri ImdsEndpoint { get; }
}
