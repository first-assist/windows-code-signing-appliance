namespace ArtifactSigning.Windows;

public enum AuthenticodeSignerTrustKind
{
    ExactCertificate,
    MicrosoftArtifactSigningPublisher,
}

public sealed class AuthenticodeTrustPolicy
{
    public AuthenticodeTrustPolicy(
        string expectedSignerThumbprint,
        WindowsTrustRevocationPolicy revocationPolicy)
        : this(
            expectedSignerThumbprint,
            revocationPolicy,
            revocationPolicy,
            expectedSignerCertificateSha256: null,
            expectedSignerSubjectPublicKeyInfoSha256: null)
    {
    }

    public AuthenticodeTrustPolicy(
        string expectedSignerThumbprint,
        WindowsTrustRevocationPolicy signerRevocationPolicy,
        WindowsTrustRevocationPolicy timestampRevocationPolicy,
        string? expectedSignerCertificateSha256,
        string? expectedSignerSubjectPublicKeyInfoSha256)
    {
        ArgumentNullException.ThrowIfNull(expectedSignerThumbprint);

        if (!WindowsContractRules.IsUpperCertificateThumbprint(expectedSignerThumbprint))
        {
            throw new ArgumentException(
                "Expected signer thumbprint must be 40 uppercase hexadecimal characters.",
                nameof(expectedSignerThumbprint));
        }

        if (!Enum.IsDefined(signerRevocationPolicy)
            || !Enum.IsDefined(timestampRevocationPolicy))
        {
            throw new ArgumentOutOfRangeException(nameof(signerRevocationPolicy));
        }

        if (timestampRevocationPolicy
                is WindowsTrustRevocationPolicy.RetainedLabPinned
            || signerRevocationPolicy
                is WindowsTrustRevocationPolicy.RetainedLabPinned
                && timestampRevocationPolicy
                    is not WindowsTrustRevocationPolicy.Online)
        {
            throw new ArgumentException(
                "Retained-lab signer trust requires online timestamp validation.");
        }

        bool retainedSigner = signerRevocationPolicy
            is WindowsTrustRevocationPolicy.RetainedLabPinned;
        if (retainedSigner
                && (!WindowsContractRules.IsLowerSha256(
                        expectedSignerCertificateSha256 ?? string.Empty)
                    || !WindowsContractRules.IsLowerSha256(
                        expectedSignerSubjectPublicKeyInfoSha256
                            ?? string.Empty))
            || !retainedSigner
                && (expectedSignerCertificateSha256 is not null
                    || expectedSignerSubjectPublicKeyInfoSha256 is not null))
        {
            throw new ArgumentException(
                "Exact signer pins are required only for retained-lab trust.");
        }

        ExpectedSignerThumbprint = expectedSignerThumbprint;
        SignerRevocationPolicy = signerRevocationPolicy;
        TimestampRevocationPolicy = timestampRevocationPolicy;
        ExpectedSignerCertificateSha256 = expectedSignerCertificateSha256;
        ExpectedSignerSubjectPublicKeyInfoSha256 =
            expectedSignerSubjectPublicKeyInfoSha256;
        SignerTrustKind = AuthenticodeSignerTrustKind.ExactCertificate;
        ExpectedPublisherSubjectNameSha256 = null;
        RequiredPublisherEnhancedKeyUsageOid = null;
        TrustedPublisherRootThumbprints = [];
    }

    private AuthenticodeTrustPolicy(
        string expectedPublisherSubjectNameSha256,
        string requiredPublisherEnhancedKeyUsageOid,
        IReadOnlyList<string> trustedPublisherRootThumbprints,
        WindowsTrustRevocationPolicy signerRevocationPolicy,
        WindowsTrustRevocationPolicy timestampRevocationPolicy)
    {
        ArgumentNullException.ThrowIfNull(expectedPublisherSubjectNameSha256);
        ArgumentNullException.ThrowIfNull(requiredPublisherEnhancedKeyUsageOid);
        ArgumentNullException.ThrowIfNull(trustedPublisherRootThumbprints);
        if (!WindowsContractRules.IsLowerSha256(
                expectedPublisherSubjectNameSha256)
            || !IsCanonicalOid(requiredPublisherEnhancedKeyUsageOid)
            || trustedPublisherRootThumbprints.Count is 0 or > 8
            || trustedPublisherRootThumbprints.Any(
                thumbprint => !WindowsContractRules
                    .IsUpperCertificateThumbprint(thumbprint))
            || trustedPublisherRootThumbprints
                .Distinct(StringComparer.Ordinal)
                .Count() != trustedPublisherRootThumbprints.Count
            || signerRevocationPolicy is not (
                WindowsTrustRevocationPolicy.Online
                or WindowsTrustRevocationPolicy.DisposableTestNoCheck)
            || timestampRevocationPolicy is not (
                WindowsTrustRevocationPolicy.Online
                or WindowsTrustRevocationPolicy.DisposableTestNoCheck))
        {
            throw new ArgumentException(
                "Microsoft Artifact Signing publisher trust is invalid.");
        }

        SignerTrustKind =
            AuthenticodeSignerTrustKind.MicrosoftArtifactSigningPublisher;
        ExpectedSignerThumbprint = null;
        SignerRevocationPolicy = signerRevocationPolicy;
        TimestampRevocationPolicy = timestampRevocationPolicy;
        ExpectedSignerCertificateSha256 = null;
        ExpectedSignerSubjectPublicKeyInfoSha256 = null;
        ExpectedPublisherSubjectNameSha256 =
            expectedPublisherSubjectNameSha256;
        RequiredPublisherEnhancedKeyUsageOid =
            requiredPublisherEnhancedKeyUsageOid;
        TrustedPublisherRootThumbprints = Array.AsReadOnly(
            trustedPublisherRootThumbprints.ToArray());
    }

    public AuthenticodeSignerTrustKind SignerTrustKind { get; }

    public string? ExpectedSignerThumbprint { get; }

    public WindowsTrustRevocationPolicy SignerRevocationPolicy { get; }

    public WindowsTrustRevocationPolicy TimestampRevocationPolicy { get; }

    public WindowsTrustRevocationPolicy RevocationPolicy =>
        SignerRevocationPolicy;

    public string? ExpectedSignerCertificateSha256 { get; }

    public string? ExpectedSignerSubjectPublicKeyInfoSha256 { get; }

    public string? ExpectedPublisherSubjectNameSha256 { get; }

    public string? RequiredPublisherEnhancedKeyUsageOid { get; }

    public IReadOnlyList<string> TrustedPublisherRootThumbprints { get; }

    public static AuthenticodeTrustPolicy
        CreateMicrosoftArtifactSigningPublisher(
            string expectedPublisherSubjectNameSha256,
            string requiredPublisherEnhancedKeyUsageOid,
            IReadOnlyList<string> trustedPublisherRootThumbprints,
            WindowsTrustRevocationPolicy signerRevocationPolicy,
            WindowsTrustRevocationPolicy timestampRevocationPolicy)
    {
        return new AuthenticodeTrustPolicy(
            expectedPublisherSubjectNameSha256,
            requiredPublisherEnhancedKeyUsageOid,
            trustedPublisherRootThumbprints,
            signerRevocationPolicy,
            timestampRevocationPolicy);
    }

    private static bool IsCanonicalOid(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 128)
        {
            return false;
        }

        string[] arcs = value.Split('.');
        return arcs.Length >= 2
            && arcs.All(arc =>
                arc.Length > 0
                && (arc.Length is 1 || arc[0] is not '0')
                && arc.All(char.IsAsciiDigit))
            && uint.TryParse(arcs[0], out uint first)
            && uint.TryParse(arcs[1], out uint second)
            && first <= 2
            && (first >= 2 || second <= 39);
    }
}
