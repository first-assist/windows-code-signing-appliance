using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace ArtifactSigning.Acceptance.Tests;

internal sealed class DisposableWindowsTestPki : IDisposable
{
    private const string CodeSigningEkuOid = "1.3.6.1.5.5.7.3.3";
    private const string TimestampingEkuOid = "1.3.6.1.5.5.7.3.8";

    private static readonly DateTimeOffset NotBefore =
        new(2026, 7, 27, 0, 0, 0, TimeSpan.Zero);

    private readonly string _machineKeyName;
    private readonly X509Certificate2 _rootCertificate;
    private readonly X509Certificate2 _codeSigningCertificate;
    private bool _disposed;

    private DisposableWindowsTestPki(
        string machineKeyName,
        X509Certificate2 rootCertificate,
        X509Certificate2 codeSigningCertificate,
        X509Certificate2 timestampCertificate)
    {
        _machineKeyName = machineKeyName;
        _rootCertificate = rootCertificate;
        _codeSigningCertificate = codeSigningCertificate;
        TimestampCertificate = timestampCertificate;
    }

    internal string CodeSigningThumbprint =>
        _codeSigningCertificate.GetCertHashString(HashAlgorithmName.SHA1);

    internal X509Certificate2 TimestampCertificate { get; }

    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = "Certificate ownership transfers to the returned fixture; the finally block disposes every failure path.")]
    internal static DisposableWindowsTestPki Create()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException();
        }

        using RSA rootKey = RSA.Create(3072);
        CertificateRequest rootRequest = new(
            $"CN=Artifact Signing Disposable Root {Guid.NewGuid():N}",
            rootKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: true,
                pathLengthConstraint: 0,
                critical: true));
        rootRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                critical: true));
        rootRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                rootRequest.PublicKey,
                critical: false));
        string machineKeyName =
            $"ArtifactSigningDisposable-{Guid.NewGuid():N}";
        X509Certificate2? rootCertificate = null;
        X509Certificate2? codeSigningCertificate = null;
        X509Certificate2? timestampCertificate = null;
        bool ownershipTransferred = false;
        try
        {
            DateTimeOffset notAfter = DateTimeOffset.UtcNow.AddDays(2);
            notAfter = new DateTimeOffset(
                notAfter.Ticks - (notAfter.Ticks % TimeSpan.TicksPerSecond),
                TimeSpan.Zero);
            using X509Certificate2 rootWithPrivateKey =
                rootRequest.CreateSelfSigned(NotBefore, notAfter);
            using CngKey machineKey = CreateNonExportableMachineKey(machineKeyName);
            using RSA codeSigningKey = new RSACng(machineKey);
            using X509Certificate2 codeSigningCertificateWithPrivateKey =
                CreateIssuedCertificate(
                    $"CN=Artifact Signing Disposable Code Signer {Guid.NewGuid():N}",
                    codeSigningKey,
                    rootWithPrivateKey,
                    CodeSigningEkuOid,
                    notAfter);

            using RSA timestampKey = RSA.Create(2048);
            timestampCertificate = CreateIssuedCertificate(
                $"CN=Artifact Signing Disposable TSA {Guid.NewGuid():N}",
                timestampKey,
                rootWithPrivateKey,
                TimestampingEkuOid,
                notAfter);
            rootCertificate = X509CertificateLoader.LoadCertificate(
                rootWithPrivateKey.RawData);
            codeSigningCertificate = X509CertificateLoader.LoadCertificate(
                codeSigningCertificateWithPrivateKey.RawData);

            AddToStore(StoreName.Root, rootCertificate);
            AddToStore(StoreName.My, codeSigningCertificateWithPrivateKey);
            AddToStore(StoreName.TrustedPublisher, codeSigningCertificate);

            DisposableWindowsTestPki result = new(
                machineKeyName,
                rootCertificate,
                codeSigningCertificate,
                timestampCertificate);
            rootCertificate = null;
            codeSigningCertificate = null;
            timestampCertificate = null;
            ownershipTransferred = true;
            return result;
        }
        finally
        {
            if (!ownershipTransferred)
            {
                if (codeSigningCertificate is not null)
                {
                    RemoveFromStore(StoreName.My, codeSigningCertificate);
                    RemoveFromStore(
                        StoreName.TrustedPublisher,
                        codeSigningCertificate);
                }

                if (rootCertificate is not null)
                {
                    RemoveFromStore(StoreName.Root, rootCertificate);
                }

                DeleteMachineKey(machineKeyName);
            }

            timestampCertificate?.Dispose();
            codeSigningCertificate?.Dispose();
            rootCertificate?.Dispose();
        }
    }

    internal void AssertCodeSigningKeyIsMachineBoundAndNonExportable()
    {
        using X509Store store = new(
            StoreName.My,
            StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        X509Certificate2Collection matches = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            CodeSigningThumbprint,
            validOnly: false);
        using X509Certificate2 storedCertificate = Assert.Single(matches);
        using RSA privateKey = Assert.IsAssignableFrom<RSA>(
            storedCertificate.GetRSAPrivateKey());
        RSACng cngKey = Assert.IsType<RSACng>(privateKey);

        Assert.True(cngKey.Key.IsMachineKey);
        Assert.Equal(CngExportPolicies.None, cngKey.Key.ExportPolicy);
        Assert.Throws<CryptographicException>(
            () => _ = privateKey.ExportPkcs8PrivateKey());
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        RemoveFromStore(StoreName.My, _codeSigningCertificate);
        RemoveFromStore(StoreName.TrustedPublisher, _codeSigningCertificate);
        RemoveFromStore(StoreName.Root, _rootCertificate);
        TimestampCertificate.Dispose();
        _codeSigningCertificate.Dispose();
        _rootCertificate.Dispose();
        DeleteMachineKey(_machineKeyName);
    }

    private static CngKey CreateNonExportableMachineKey(string keyName)
    {
        CngKeyCreationParameters creation = new()
        {
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey,
            KeyUsage = CngKeyUsages.Signing,
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
        };
        creation.Parameters.Add(
            new CngProperty(
                "Length",
                BitConverter.GetBytes(2048),
                CngPropertyOptions.None));
        return CngKey.Create(
            CngAlgorithm.Rsa,
            keyName,
            creation);
    }

    private static X509Certificate2 CreateIssuedCertificate(
        string subject,
        RSA subjectKey,
        X509Certificate2 issuer,
        string enhancedKeyUsageOid,
        DateTimeOffset notAfter)
    {
        CertificateRequest request = new(
            subject,
            subjectKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));
        OidCollection usages = new()
        {
            new Oid(enhancedKeyUsageOid),
        };
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                usages,
                critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                critical: false));

        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
        using X509Certificate2 issued = request.Create(
            issuer,
            NotBefore,
            notAfter,
            serialNumber);
        return issued.CopyWithPrivateKey(subjectKey);
    }

    private static void AddToStore(
        StoreName storeName,
        X509Certificate2 certificate)
    {
        using X509Store store = new(storeName, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
    }

    private static void RemoveFromStore(
        StoreName storeName,
        X509Certificate2 certificate)
    {
        try
        {
            using X509Store store = new(storeName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection matches = store.Certificates.Find(
                X509FindType.FindByThumbprint,
                certificate.GetCertHashString(HashAlgorithmName.SHA1),
                validOnly: false);
            foreach (X509Certificate2 match in matches)
            {
                using (match)
                {
                    store.Remove(match);
                }
            }
        }
        catch (CryptographicException)
        {
            // The disposable runner teardown will remove any remaining machine state.
        }
    }

    private static void DeleteMachineKey(string keyName)
    {
        try
        {
            if (!CngKey.Exists(
                    keyName,
                    CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    CngKeyOpenOptions.MachineKey))
            {
                return;
            }

            using CngKey key = CngKey.Open(
                keyName,
                CngProvider.MicrosoftSoftwareKeyStorageProvider,
                CngKeyOpenOptions.MachineKey);
            key.Delete();
        }
        catch (CryptographicException)
        {
            // The disposable runner teardown will remove any remaining machine state.
        }
    }
}
