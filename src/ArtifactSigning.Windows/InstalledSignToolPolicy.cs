namespace ArtifactSigning.Windows;

public sealed class InstalledSignToolPolicy
{
    public const int MaximumTimestampUrlCharacters = 512;
    public static readonly TimeSpan MaximumTimeout = TimeSpan.FromSeconds(120);

    public InstalledSignToolPolicy(
        string absolutePath,
        string sha256,
        Version fileVersion,
        string signerThumbprint,
        Uri timestampUrl,
        TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(absolutePath);
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentNullException.ThrowIfNull(fileVersion);
        ArgumentNullException.ThrowIfNull(signerThumbprint);
        ArgumentNullException.ThrowIfNull(timestampUrl);

        if (!WindowsContractRules.IsAbsoluteLeafPath(absolutePath, "signtool.exe"))
        {
            throw new ArgumentException(
                "SignTool path must be absolute and end with signtool.exe.",
                nameof(absolutePath));
        }

        if (!WindowsContractRules.IsLowerSha256(sha256))
        {
            throw new ArgumentException(
                "SignTool digest must be canonical lowercase SHA-256.",
                nameof(sha256));
        }

        if (fileVersion.Major < 0
            || fileVersion.Minor < 0
            || fileVersion.Build < 0
            || fileVersion.Revision < 0)
        {
            throw new ArgumentException(
                "SignTool version must contain four nonnegative components.",
                nameof(fileVersion));
        }

        if (!WindowsContractRules.IsUpperCertificateThumbprint(signerThumbprint))
        {
            throw new ArgumentException(
                "Signer thumbprint must be 40 uppercase hexadecimal characters.",
                nameof(signerThumbprint));
        }

        if (!IsAcceptedTimestampUrl(timestampUrl))
        {
            throw new ArgumentException(
                "Timestamp URL must be a bounded absolute HTTP(S) endpoint without credentials, query, or fragment.",
                nameof(timestampUrl));
        }

        if (timeout < TimeSpan.FromSeconds(1) || timeout > MaximumTimeout)
        {
            throw new ArgumentOutOfRangeException(
                nameof(timeout),
                "SignTool timeout must be from one through 120 seconds.");
        }

        AbsolutePath = absolutePath;
        Sha256 = sha256;
        FileVersion = new Version(
            fileVersion.Major,
            fileVersion.Minor,
            fileVersion.Build,
            fileVersion.Revision);
        SignerThumbprint = signerThumbprint;
        TimestampUrl = new Uri(timestampUrl.AbsoluteUri, UriKind.Absolute);
        Timeout = timeout;
    }

    public string AbsolutePath { get; }

    public string Sha256 { get; }

    public Version FileVersion { get; }

    public string SignerThumbprint { get; }

    public Uri TimestampUrl { get; }

    public TimeSpan Timeout { get; }

    private static bool IsAcceptedTimestampUrl(Uri timestampUrl)
    {
        return timestampUrl.IsAbsoluteUri
            && timestampUrl.AbsoluteUri.Length <= MaximumTimestampUrlCharacters
            && (timestampUrl.Scheme == Uri.UriSchemeHttps
                || timestampUrl.Scheme == Uri.UriSchemeHttp)
            && !string.IsNullOrWhiteSpace(timestampUrl.Host)
            && string.IsNullOrEmpty(timestampUrl.UserInfo)
            && string.IsNullOrEmpty(timestampUrl.Query)
            && string.IsNullOrEmpty(timestampUrl.Fragment);
    }
}
