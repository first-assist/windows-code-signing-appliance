using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Gateway;

public static class GatewayCertificateStore
{
    private const string SoftwareKeyStorageProvider =
        "Microsoft Software Key Storage Provider";
    private const string ServerAuthenticationEku =
        "1.3.6.1.5.5.7.3.1";

    public static X509Certificate2 LoadServerCertificate(
        string thumbprint)
    {
        X509Certificate2 certificate = LoadUnique(
            StoreName.My,
            thumbprint);
        try
        {
            if (!certificate.HasPrivateKey
                || !IsNonExportableMachineCngKey(certificate)
                || !HasDigitalSignatureUsage(certificate)
                || !HasEnhancedKeyUsage(
                    certificate,
                    ServerAuthenticationEku)
                || !IsCurrent(certificate))
            {
                throw new InvalidOperationException(
                    "Installed Gateway TLS certificate is invalid.");
            }

            return certificate;
        }
        catch
        {
            certificate.Dispose();
            throw;
        }
    }

    public static CmsTrustPolicy CreateTrustPolicy(
        GatewayTrustConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        IReadOnlyList<X509Certificate2> roots =
            LoadPublicCertificates(
                StoreName.Root,
                configuration.TrustedRootThumbprints,
                requireCertificateAuthority: true);
        IReadOnlyList<X509Certificate2> extras =
            LoadPublicCertificates(
                StoreName.CertificateAuthority,
                configuration.ExtraCertificateThumbprints,
                requireCertificateAuthority: false);
        try
        {
            return new CmsTrustPolicy(
                configuration.ExpectedSignerSpkiSha256,
                configuration.RequiredEnhancedKeyUsageOid,
                roots,
                configuration.RevocationPolicy,
                TimeSpan.FromSeconds(
                    configuration.UrlRetrievalTimeoutSeconds),
                extras,
                configuration.ExpectedSignerCertificateSha256);
        }
        finally
        {
            DisposeAll(roots);
            DisposeAll(extras);
        }
    }

    public static string GetPrivateKeyFilePath(
        X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Gateway private-key storage is Windows-only.");
        }

        using RSA? rsa = certificate.GetRSAPrivateKey();
        if (rsa is not RSACng rsaCng)
        {
            throw new InvalidOperationException(
                "Installed Gateway private key is not a machine CNG key.");
        }

        CngKey key = rsaCng.Key;
        string? uniqueName = key.UniqueName;
        if (string.IsNullOrWhiteSpace(uniqueName)
            || uniqueName.Length > 128
            || !string.Equals(
                Path.GetFileName(uniqueName),
                uniqueName,
                StringComparison.Ordinal)
            || uniqueName.Any(character =>
                !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '_'))
        {
            throw new InvalidOperationException(
                "Gateway TLS key storage identity is invalid.");
        }

        string commonApplicationData = Environment.GetFolderPath(
            Environment.SpecialFolder.CommonApplicationData);
        return Path.Combine(
            commonApplicationData,
            "Microsoft",
            "Crypto",
            "Keys",
            uniqueName);
    }

    private static ReadOnlyCollection<X509Certificate2>
        LoadPublicCertificates(
            StoreName storeName,
            IReadOnlyList<string> thumbprints,
            bool requireCertificateAuthority)
    {
        List<X509Certificate2> certificates = [];
        try
        {
            foreach (string thumbprint in thumbprints)
            {
                X509Certificate2 certificate = LoadUnique(
                    storeName,
                    thumbprint);
                if (certificate.HasPrivateKey
                    || requireCertificateAuthority
                        && !IsCertificateAuthority(certificate))
                {
                    certificate.Dispose();
                    throw new InvalidOperationException(
                        "Installed Gateway public certificate is invalid.");
                }

                certificates.Add(certificate);
            }

            return certificates.AsReadOnly();
        }
        catch
        {
            DisposeAll(certificates);
            throw;
        }
    }

    private static X509Certificate2 LoadUnique(
        StoreName storeName,
        string thumbprint)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Gateway certificate resolution is Windows-only.");
        }

        using X509Store store = new(
            storeName,
            StoreLocation.LocalMachine);
        store.Open(
            OpenFlags.ReadOnly
                | OpenFlags.OpenExistingOnly);
        X509Certificate2Collection matches =
            store.Certificates.Find(
                X509FindType.FindByThumbprint,
                thumbprint,
                validOnly: false);
        if (matches.Count is not 1
            || !string.Equals(
                matches[0].Thumbprint,
                thumbprint,
                StringComparison.Ordinal))
        {
            DisposeAll(matches);
            throw new InvalidOperationException(
                "Installed Gateway certificate selection is missing or ambiguous.");
        }

        X509Certificate2 selected = matches[0];
        foreach (X509Certificate2 match in matches)
        {
            if (!ReferenceEquals(match, selected))
            {
                match.Dispose();
            }
        }

        return selected;
    }

    private static bool IsNonExportableMachineCngKey(
        X509Certificate2 certificate)
    {
        try
        {
            using RSA? rsa = certificate.GetRSAPrivateKey();
            if (rsa is not RSACng rsaCng)
            {
                return false;
            }

            CngKey key = rsaCng.Key;
            CngProvider? provider = key.Provider;
            return key.IsMachineKey
                && !key.IsEphemeral
                && provider is not null
                && string.Equals(
                    provider.Provider,
                    SoftwareKeyStorageProvider,
                    StringComparison.Ordinal)
                && key.ExportPolicy is CngExportPolicies.None;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool HasDigitalSignatureUsage(
        X509Certificate2 certificate)
    {
        X509KeyUsageExtension[] usages = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .ToArray();
        return usages.Length is 1
            && usages[0].KeyUsages.HasFlag(
                X509KeyUsageFlags.DigitalSignature);
    }

    private static bool HasEnhancedKeyUsage(
        X509Certificate2 certificate,
        string requiredOid)
    {
        X509EnhancedKeyUsageExtension[] usages =
            certificate.Extensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .ToArray();
        return usages.Length is 1
            && usages[0].EnhancedKeyUsages
                .Cast<Oid>()
                .Count(item => string.Equals(
                    item.Value,
                    requiredOid,
                    StringComparison.Ordinal)) is 1;
    }

    private static bool IsCertificateAuthority(
        X509Certificate2 certificate)
    {
        X509BasicConstraintsExtension[] constraints =
            certificate.Extensions
                .OfType<X509BasicConstraintsExtension>()
                .ToArray();
        return constraints.Length is 1
            && constraints[0].CertificateAuthority;
    }

    private static bool IsCurrent(X509Certificate2 certificate)
    {
        DateTime now = DateTime.UtcNow;
        return certificate.NotBefore.ToUniversalTime() <= now
            && now <= certificate.NotAfter.ToUniversalTime();
    }

    private static void DisposeAll(
        IEnumerable<X509Certificate2> certificates)
    {
        foreach (X509Certificate2 certificate in certificates)
        {
            certificate.Dispose();
        }
    }
}
