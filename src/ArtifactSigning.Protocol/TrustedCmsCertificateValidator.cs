using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.Protocol;

internal static class TrustedCmsCertificateValidator
{
    internal static TrustedDetachedCmsError Validate(
        X509Certificate2 signerCertificate,
        X509Certificate2Collection embeddedCertificates,
        CmsTrustPolicy trustPolicy,
        DateTimeOffset verificationTime)
    {
        if (trustPolicy.ExpectedSignerCertificateSha256 is not null
            && !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(
                    CertificateIdentity.ComputeCertificateSha256(
                        signerCertificate)),
                Convert.FromHexString(
                    trustPolicy.ExpectedSignerCertificateSha256)))
        {
            return TrustedDetachedCmsError.SignerCertificateMismatch;
        }

        if (!HasEndEntityProfile(signerCertificate))
        {
            return TrustedDetachedCmsError.SignerCertificateProfileInvalid;
        }

        if (!HasRequiredEnhancedKeyUsage(
                signerCertificate,
                trustPolicy.RequiredEnhancedKeyUsageOid))
        {
            return TrustedDetachedCmsError.RequiredEnhancedKeyUsageMissing;
        }

        return ValidateChain(
            signerCertificate,
            embeddedCertificates,
            trustPolicy,
            verificationTime);
    }

    private static bool HasEndEntityProfile(
        X509Certificate2 signerCertificate)
    {
        X509BasicConstraintsExtension[] constraints = signerCertificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .ToArray();
        return constraints.Length is 1 && !constraints[0].CertificateAuthority;
    }

    private static bool HasRequiredEnhancedKeyUsage(
        X509Certificate2 signerCertificate,
        string requiredOid)
    {
        X509EnhancedKeyUsageExtension[] extensions = signerCertificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .ToArray();

        return extensions.Length is 1
            && extensions[0].EnhancedKeyUsages
                .Cast<Oid>()
                .Any(oid => string.Equals(
                    oid.Value,
                    requiredOid,
                    StringComparison.Ordinal));
    }

    private static TrustedDetachedCmsError ValidateChain(
        X509Certificate2 signerCertificate,
        X509Certificate2Collection embeddedCertificates,
        CmsTrustPolicy trustPolicy,
        DateTimeOffset verificationTime)
    {
        IReadOnlyList<X509Certificate2> trustedRoots =
            trustPolicy.CreateTrustedRoots();
        IReadOnlyList<X509Certificate2> configuredExtras =
            trustPolicy.CreateExtraCertificates();

        try
        {
            using X509Chain chain = new();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode =
                MapRevocationMode(trustPolicy.RevocationPolicy);
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = verificationTime.UtcDateTime;
            chain.ChainPolicy.UrlRetrievalTimeout =
                trustPolicy.UrlRetrievalTimeout;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.ApplicationPolicy.Add(
                new Oid(trustPolicy.RequiredEnhancedKeyUsageOid));
            chain.ChainPolicy.CustomTrustStore.AddRange(
                trustedRoots.ToArray());
            chain.ChainPolicy.ExtraStore.AddRange(
                configuredExtras.ToArray());

            foreach (X509Certificate2 embedded in embeddedCertificates)
            {
                if (!embedded.RawDataMemory.Span.SequenceEqual(
                        signerCertificate.RawDataMemory.Span))
                {
                    chain.ChainPolicy.ExtraStore.Add(embedded);
                }
            }

            bool isValid = chain.Build(signerCertificate);
            return isValid
                ? TrustedDetachedCmsError.None
                : MapChainError(chain.ChainStatus);
        }
        catch (CryptographicException)
        {
            return TrustedDetachedCmsError.ChainInvalid;
        }
        finally
        {
            DisposeCertificates(trustedRoots);
            DisposeCertificates(configuredExtras);
        }
    }

    private static X509RevocationMode MapRevocationMode(
        CmsRevocationPolicy policy)
    {
        return policy switch
        {
            CmsRevocationPolicy.Online => X509RevocationMode.Online,
            CmsRevocationPolicy.Offline => X509RevocationMode.Offline,
            CmsRevocationPolicy.DisposableTestNoCheck =>
                X509RevocationMode.NoCheck,
            CmsRevocationPolicy.RetainedLabPinned =>
                X509RevocationMode.NoCheck,
            _ => throw new ArgumentOutOfRangeException(nameof(policy)),
        };
    }

    private static TrustedDetachedCmsError MapChainError(
        IEnumerable<X509ChainStatus> statuses)
    {
        X509ChainStatusFlags combined = statuses.Aggregate(
            X509ChainStatusFlags.NoError,
            (current, status) => current | status.Status);

        if (combined.HasFlag(X509ChainStatusFlags.Revoked))
        {
            return TrustedDetachedCmsError.CertificateRevoked;
        }

        if (combined.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown)
            || combined.HasFlag(X509ChainStatusFlags.OfflineRevocation))
        {
            return TrustedDetachedCmsError.RevocationUncertain;
        }

        if (combined.HasFlag(X509ChainStatusFlags.NotTimeValid)
            || combined.HasFlag(X509ChainStatusFlags.NotTimeNested))
        {
            return TrustedDetachedCmsError.CertificateNotValid;
        }

        if (combined.HasFlag(X509ChainStatusFlags.NotValidForUsage))
        {
            return TrustedDetachedCmsError.RequiredEnhancedKeyUsageMissing;
        }

        return TrustedDetachedCmsError.ChainInvalid;
    }

    private static void DisposeCertificates(
        IEnumerable<X509Certificate2> certificates)
    {
        foreach (X509Certificate2 certificate in certificates)
        {
            certificate.Dispose();
        }
    }
}
