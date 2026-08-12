using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.Protocol;

public enum CmsRevocationPolicy
{
    Online,
    Offline,
    DisposableTestNoCheck,
    RetainedLabPinned,
}

public sealed class CmsTrustPolicy
{
    public const int MaximumTrustedRoots = 8;
    public const int MaximumExtraCertificates = 16;

    private readonly byte[][] _trustedRootCertificates;
    private readonly byte[][] _extraCertificates;

    public CmsTrustPolicy(
        string expectedSignerSpkiSha256,
        string requiredEnhancedKeyUsageOid,
        IEnumerable<X509Certificate2> trustedRoots,
        CmsRevocationPolicy revocationPolicy,
        TimeSpan urlRetrievalTimeout,
        IEnumerable<X509Certificate2>? extraCertificates = null,
        string? expectedSignerCertificateSha256 = null)
    {
        ArgumentNullException.ThrowIfNull(expectedSignerSpkiSha256);
        ArgumentNullException.ThrowIfNull(requiredEnhancedKeyUsageOid);
        ArgumentNullException.ThrowIfNull(trustedRoots);

        if (!StrictJsonRules.IsLowerHex(expectedSignerSpkiSha256, 64))
        {
            throw new ArgumentException(
                "Expected signer identity must be canonical SHA-256.",
                nameof(expectedSignerSpkiSha256));
        }

        if (!IsCanonicalOid(requiredEnhancedKeyUsageOid))
        {
            throw new ArgumentException(
                "Required enhanced key usage must be a canonical numeric OID.",
                nameof(requiredEnhancedKeyUsageOid));
        }

        if (!Enum.IsDefined(revocationPolicy))
        {
            throw new ArgumentOutOfRangeException(nameof(revocationPolicy));
        }

        if (revocationPolicy is CmsRevocationPolicy.RetainedLabPinned)
        {
            if (!StrictJsonRules.IsLowerHex(
                    expectedSignerCertificateSha256 ?? string.Empty,
                    64))
            {
                throw new ArgumentException(
                    "Retained-lab trust requires an exact signer certificate SHA-256.",
                    nameof(expectedSignerCertificateSha256));
            }
        }
        else if (expectedSignerCertificateSha256 is not null)
        {
            throw new ArgumentException(
                "Only retained-lab pinned trust accepts a signer certificate SHA-256.",
                nameof(expectedSignerCertificateSha256));
        }

        if (urlRetrievalTimeout < TimeSpan.FromSeconds(1)
            || urlRetrievalTimeout > TimeSpan.FromSeconds(15))
        {
            throw new ArgumentOutOfRangeException(
                nameof(urlRetrievalTimeout),
                "URL retrieval timeout must be from one through fifteen seconds.");
        }

        X509Certificate2[] roots = trustedRoots.ToArray();
        if (roots.Length is 0 or > MaximumTrustedRoots)
        {
            throw new ArgumentException(
                $"Trust policy requires from one through {MaximumTrustedRoots} roots.",
                nameof(trustedRoots));
        }

        X509Certificate2[] extras = extraCertificates?.ToArray() ?? [];
        if (extras.Length > MaximumExtraCertificates)
        {
            throw new ArgumentException(
                $"Trust policy accepts at most {MaximumExtraCertificates} extra certificates.",
                nameof(extraCertificates));
        }

        ValidateCertificatesArePublicOnly(roots, nameof(trustedRoots));
        ValidateCertificatesArePublicOnly(extras, nameof(extraCertificates));
        ValidateRoots(roots, nameof(trustedRoots));

        ExpectedSignerSpkiSha256 = expectedSignerSpkiSha256;
        ExpectedSignerCertificateSha256 = expectedSignerCertificateSha256;
        RequiredEnhancedKeyUsageOid = requiredEnhancedKeyUsageOid;
        RevocationPolicy = revocationPolicy;
        UrlRetrievalTimeout = urlRetrievalTimeout;
        _trustedRootCertificates = CopyRawCertificates(roots);
        _extraCertificates = CopyRawCertificates(extras);
    }

    public string ExpectedSignerSpkiSha256 { get; }

    public string? ExpectedSignerCertificateSha256 { get; }

    public string RequiredEnhancedKeyUsageOid { get; }

    public CmsRevocationPolicy RevocationPolicy { get; }

    public TimeSpan UrlRetrievalTimeout { get; }

    internal IReadOnlyList<X509Certificate2> CreateTrustedRoots()
    {
        return _trustedRootCertificates
            .Select(encoded => X509CertificateLoader.LoadCertificate(encoded))
            .ToArray();
    }

    internal IReadOnlyList<X509Certificate2> CreateExtraCertificates()
    {
        return _extraCertificates
            .Select(encoded => X509CertificateLoader.LoadCertificate(encoded))
            .ToArray();
    }

    private static byte[][] CopyRawCertificates(
        IEnumerable<X509Certificate2> certificates)
    {
        return certificates.Select(certificate => certificate.RawData).ToArray();
    }

    private static void ValidateCertificatesArePublicOnly(
        IEnumerable<X509Certificate2> certificates,
        string parameterName)
    {
        foreach (X509Certificate2 certificate in certificates)
        {
            if (certificate is null)
            {
                throw new ArgumentException(
                    "Certificate collections cannot contain null values.",
                    parameterName);
            }

            if (certificate.HasPrivateKey)
            {
                throw new ArgumentException(
                    "CMS trust policy accepts public certificates only.",
                    parameterName);
            }
        }
    }

    private static void ValidateRoots(
        IEnumerable<X509Certificate2> roots,
        string parameterName)
    {
        HashSet<string> identities = new(StringComparer.Ordinal);
        foreach (X509Certificate2 root in roots)
        {
            X509BasicConstraintsExtension[] constraints = root.Extensions
                .OfType<X509BasicConstraintsExtension>()
                .ToArray();
            if (constraints.Length is not 1 || !constraints[0].CertificateAuthority)
            {
                throw new ArgumentException(
                    "Every CMS trust root must be a certificate authority.",
                    parameterName);
            }

            if (!identities.Add(CertificateIdentity.ComputeCertificateSha256(root)))
            {
                throw new ArgumentException(
                    "CMS trust roots must be unique.",
                    parameterName);
            }
        }
    }

    private static bool IsCanonicalOid(string value)
    {
        if (value.Length is 0 or > 128)
        {
            return false;
        }

        string[] arcs = value.Split('.');
        if (arcs.Length < 2 || !IsCanonicalArc(arcs[0]) || !IsCanonicalArc(arcs[1]))
        {
            return false;
        }

        if (!uint.TryParse(arcs[0], out uint first) || first > 2
            || !uint.TryParse(arcs[1], out uint second) || first < 2 && second > 39)
        {
            return false;
        }

        return arcs.Skip(2).All(IsCanonicalArc);
    }

    private static bool IsCanonicalArc(string arc)
    {
        return arc.Length > 0
            && (arc.Length is 1 || arc[0] is not '0')
            && arc.All(char.IsAsciiDigit);
    }
}
