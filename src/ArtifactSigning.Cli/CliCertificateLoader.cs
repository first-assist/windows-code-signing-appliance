using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Cli;

internal static class CliCertificateLoader
{
    private const string ClientAuthenticationEkuOid =
        "1.3.6.1.5.5.7.3.2";
    private const int MaximumPemBytes = 1024 * 1024;
    private const int MaximumPasswordBytes = 4096;
    private static readonly UTF8Encoding StrictUtf8 =
        new(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true);

    internal static X509Certificate2 LoadClientIdentity(
        CliIdentityConfiguration configuration,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        X509Certificate2 certificate =
            configuration.Provider switch
            {
                CliIdentityProvider.PemFiles =>
                    LoadPemIdentity(configuration),
                CliIdentityProvider
                    .WindowsCurrentUserStore =>
                    LoadWindowsIdentity(configuration),
                _ => throw new InvalidDataException(
                    "Client identity provider is invalid."),
            };
        try
        {
            ValidateClientIdentity(certificate, now);
            return certificate;
        }
        catch
        {
            certificate.Dispose();
            throw;
        }
    }

    internal static CmsTrustPolicy CreateTrustPolicy(
        CliTrustConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        X509Certificate2[] roots =
            configuration.TrustedRootCertificatePaths
                .Select(LoadPublicCertificate)
                .ToArray();
        X509Certificate2[] extra =
            configuration.ExtraCertificatePaths
                .Select(LoadPublicCertificate)
                .ToArray();
        try
        {
            return new CmsTrustPolicy(
                configuration.ExpectedSignerSpkiSha256,
                configuration.RequiredEnhancedKeyUsageOid,
                roots,
                configuration.RevocationPolicy,
                TimeSpan.FromSeconds(
                    configuration
                        .UrlRetrievalTimeoutSeconds),
                extra,
                configuration.ExpectedSignerCertificateSha256);
        }
        finally
        {
            foreach (X509Certificate2 certificate
                     in roots.Concat(extra))
            {
                certificate.Dispose();
            }
        }
    }

    internal static byte[] SignCms(
        ReadOnlySpan<byte> content,
        X509Certificate2 certificate,
        bool detached)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        SignedCms signedCms = new(
            new ContentInfo(content.ToArray()),
            detached);
        CmsSigner signer = new(
            SubjectIdentifierType.SubjectKeyIdentifier,
            certificate)
        {
            DigestAlgorithm =
                new Oid("2.16.840.1.101.3.4.2.1"),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        signedCms.ComputeSignature(signer, silent: true);
        byte[] signature = signedCms.Encode();
        if (signature.Length is <= 0
            or > DetachedCmsSignatureVerifier
                .MaximumSignatureBytes)
        {
            throw new CryptographicException(
                "Client CMS signature exceeds its protocol bound.");
        }

        return signature;
    }

    private static X509Certificate2 LoadPemIdentity(
        CliIdentityConfiguration configuration)
    {
        string certificatePath =
            configuration.CertificatePath!;
        string privateKeyPath =
            configuration.PrivateKeyPath!;
        CliFileSecurity.ValidateDirectRegularFile(
            certificatePath,
            MaximumPemBytes);
        CliFileSecurity.RequireOwnerOnlyFile(
            privateKeyPath,
            MaximumPemBytes);
        byte[] certificateBytes =
            CliFileSecurity.ReadBounded(
                certificatePath,
                MaximumPemBytes);
        byte[] keyBytes = CliFileSecurity.ReadBounded(
            privateKeyPath,
            MaximumPemBytes);
        string certificatePem =
            StrictUtf8.GetString(certificateBytes);
        char[] keyCharacters =
            StrictUtf8.GetChars(keyBytes);
        try
        {
            if (configuration.PrivateKeyPasswordFile
                is null)
            {
                return X509Certificate2.CreateFromPem(
                    certificatePem.AsSpan(),
                    keyCharacters);
            }

            CliFileSecurity.RequireOwnerOnlyFile(
                configuration.PrivateKeyPasswordFile,
                MaximumPasswordBytes);
            byte[] passwordBytes =
                CliFileSecurity.ReadBounded(
                    configuration.PrivateKeyPasswordFile,
                    MaximumPasswordBytes);
            char[] passwordCharacters =
                StrictUtf8.GetChars(passwordBytes);
            int passwordLength =
                passwordCharacters.Length;
            while (passwordLength > 0
                   && passwordCharacters[
                       passwordLength - 1] is
                       '\r' or '\n')
            {
                passwordLength--;
            }

            try
            {
                if (passwordLength is 0)
                {
                    throw new InvalidDataException(
                        "Private-key password file is empty.");
                }

                return X509Certificate2
                    .CreateFromEncryptedPem(
                        certificatePem.AsSpan(),
                        passwordCharacters.AsSpan(
                            0,
                            passwordLength),
                        keyCharacters);
            }
            finally
            {
                passwordCharacters.AsSpan().Clear();
                CryptographicOperations.ZeroMemory(
                    passwordBytes);
            }
        }
        finally
        {
            keyCharacters.AsSpan().Clear();
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    private static X509Certificate2 LoadWindowsIdentity(
        CliIdentityConfiguration configuration)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The Windows certificate provider requires Windows.");
        }

        using X509Store store = new(
            StoreName.My,
            StoreLocation.CurrentUser);
        store.Open(OpenFlags.OpenExistingOnly
            | OpenFlags.ReadOnly);
        X509Certificate2[] matches = store.Certificates
            .Find(
                X509FindType.FindByThumbprint,
                configuration.CertificateThumbprint!,
                validOnly: false)
            .OfType<X509Certificate2>()
            .Where(item => string.Equals(
                item.Thumbprint,
                configuration.CertificateThumbprint,
                StringComparison.Ordinal))
            .ToArray();
        if (matches.Length is not 1)
        {
            foreach (X509Certificate2 match in matches)
            {
                match.Dispose();
            }

            throw new InvalidDataException(
                "Client certificate selection is not unique.");
        }

        return matches[0];
    }

    private static X509Certificate2 LoadPublicCertificate(
        string path)
    {
        byte[] bytes = CliFileSecurity.ReadBounded(
            path,
            MaximumPemBytes);
        X509Certificate2 certificate =
            bytes.AsSpan().IndexOf(
                "-----BEGIN CERTIFICATE-----"u8) >= 0
                ? X509Certificate2.CreateFromPem(
                    StrictUtf8.GetString(bytes))
                : X509CertificateLoader
                    .LoadCertificate(bytes);
        if (certificate.HasPrivateKey)
        {
            certificate.Dispose();
            throw new InvalidDataException(
                "A client trust certificate contains a private key.");
        }

        return certificate;
    }

    private static void ValidateClientIdentity(
        X509Certificate2 certificate,
        DateTimeOffset now)
    {
        DateTime utcNow = now.UtcDateTime;
        X509KeyUsageExtension? keyUsage =
            certificate.Extensions
                .OfType<X509KeyUsageExtension>()
                .SingleOrDefault();
        X509EnhancedKeyUsageExtension? enhancedKeyUsage =
            certificate.Extensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .SingleOrDefault();
        if (!certificate.HasPrivateKey
            || utcNow < certificate.NotBefore.ToUniversalTime()
            || utcNow >= certificate.NotAfter.ToUniversalTime()
            || keyUsage is null
            || !keyUsage.KeyUsages.HasFlag(
                X509KeyUsageFlags.DigitalSignature)
            || enhancedKeyUsage is null
            || !enhancedKeyUsage.EnhancedKeyUsages
                .OfType<Oid>()
                .Any(item => string.Equals(
                    item.Value,
                    ClientAuthenticationEkuOid,
                    StringComparison.Ordinal)))
        {
            throw new CryptographicException(
                "Client certificate profile is invalid.");
        }
    }
}
