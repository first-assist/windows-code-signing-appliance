using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.DisposableLab;

internal sealed record DisposableCertificateEvidence(
    string Thumbprint,
    string CertificateSha256,
    string SubjectPublicKeyInfoSha256);

internal sealed record DisposableLabEvidence(
    string Format,
    string CreatedUtc,
    string RootThumbprint,
    string RootCertificatePath,
    DisposableCertificateEvidence GatewayTls,
    DisposableCertificateEvidence Receipt,
    DisposableCertificateEvidence Authenticode,
    DisposableCertificateEvidence Submitter,
    DisposableCertificateEvidence Approver,
    DisposableCertificateEvidence Auditor,
    DisposableCertificateEvidence Timestamp);

internal static class DisposableIdentityProvisioner
{
    private const string ClientAuthenticationEku =
        "1.3.6.1.5.5.7.3.2";
    private const string ServerAuthenticationEku =
        "1.3.6.1.5.5.7.3.1";
    private const string CodeSigningEku =
        "1.3.6.1.5.5.7.3.3";
    private const string TimestampingEku =
        "1.3.6.1.5.5.7.3.8";

    internal static DisposableLabEvidence Prepare()
    {
        if (File.Exists(DisposableLabPaths.Evidence)
            || Directory.Exists(DisposableLabPaths.PublicRoot))
        {
            throw new InvalidOperationException(
                "Disposable identities already exist.");
        }

        Directory.CreateDirectory(DisposableLabPaths.PublicRoot);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset notBefore = now.AddMinutes(-5);
        DateTimeOffset notAfter = now.AddDays(2);
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
                X509KeyUsageFlags.KeyCertSign
                | X509KeyUsageFlags.CrlSign,
                critical: true));
        rootRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                rootRequest.PublicKey,
                critical: false));
        using X509Certificate2 rootWithPrivateKey =
            rootRequest.CreateSelfSigned(notBefore, notAfter);
        using X509Certificate2 publicRoot =
            X509CertificateLoader.LoadCertificate(
                rootWithPrivateKey.RawData);
        AddToStore(
            StoreName.Root,
            StoreLocation.LocalMachine,
            publicRoot);
        File.WriteAllBytes(
            DisposableLabPaths.RootCertificate,
            publicRoot.RawData);

        DisposableCertificateEvidence gateway =
            CreateLeaf(
                "Gateway TLS",
                ServerAuthenticationEku,
                machineKey: true,
                rootWithPrivateKey,
                notBefore,
                notAfter,
                addLoopbackSan: true);
        DisposableCertificateEvidence receipt =
            CreateLeaf(
                "Receipt",
                ClientAuthenticationEku,
                machineKey: true,
                rootWithPrivateKey,
                notBefore,
                notAfter);
        DisposableCertificateEvidence authenticode =
            CreateLeaf(
                "Authenticode",
                CodeSigningEku,
                machineKey: true,
                rootWithPrivateKey,
                notBefore,
                notAfter,
                addToTrustedPublisher: true);
        DisposableCertificateEvidence submitter =
            CreateLeaf(
                "Submitter",
                ClientAuthenticationEku,
                machineKey: false,
                rootWithPrivateKey,
                notBefore,
                notAfter);
        DisposableCertificateEvidence approver =
            CreateLeaf(
                "Approver",
                ClientAuthenticationEku,
                machineKey: false,
                rootWithPrivateKey,
                notBefore,
                notAfter);
        DisposableCertificateEvidence auditor =
            CreateLeaf(
                "Auditor",
                ClientAuthenticationEku,
                machineKey: false,
                rootWithPrivateKey,
                notBefore,
                notAfter);
        DisposableCertificateEvidence timestamp =
            CreateLeaf(
                "Timestamp",
                TimestampingEku,
                machineKey: true,
                rootWithPrivateKey,
                notBefore,
                notAfter);

        string rootThumbprint = publicRoot.GetCertHashString(
            HashAlgorithmName.SHA1);
        DisposableLabEvidence evidence = new(
            "ArtifactSigningDisposableLabEvidenceV1",
            FormatWholeSecond(now),
            rootThumbprint,
            DisposableLabPaths.RootCertificate,
            gateway,
            receipt,
            authenticode,
            submitter,
            approver,
            auditor,
            timestamp);
        WriteConfigurationFiles(evidence);
        File.WriteAllText(
            DisposableLabPaths.Evidence,
            JsonSerializer.Serialize(evidence, DisposableJson.Options)
                + Environment.NewLine,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return evidence;
    }

    private static DisposableCertificateEvidence CreateLeaf(
        string role,
        string enhancedKeyUsageOid,
        bool machineKey,
        X509Certificate2 issuer,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        bool addLoopbackSan = false,
        bool addToTrustedPublisher = false)
    {
        string keyName = string.Concat(
            "ArtifactSigningDisposable-",
            role.Replace(" ", string.Empty, StringComparison.Ordinal),
            "-",
            Guid.NewGuid().ToString("N"));
        using CngKey key = CreateNonExportableKey(
            keyName,
            machineKey);
        using RSA rsa = new RSACng(key);
        CertificateRequest request = new(
            $"CN=Artifact Signing Disposable {role} {Guid.NewGuid():N}",
            rsa,
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
        if (addLoopbackSan)
        {
            SubjectAlternativeNameBuilder alternativeNames =
                new();
            alternativeNames.AddIpAddress(IPAddress.Loopback);
            alternativeNames.AddDnsName("localhost");
            request.CertificateExtensions.Add(
                alternativeNames.Build(critical: false));
        }

        using X509Certificate2 publicCertificate = request.Create(
            issuer,
            notBefore,
            notAfter,
            RandomNumberGenerator.GetBytes(16));
        using X509Certificate2 privateCertificate =
            publicCertificate.CopyWithPrivateKey(rsa);
        StoreLocation location = machineKey
            ? StoreLocation.LocalMachine
            : StoreLocation.CurrentUser;
        AddToStore(StoreName.My, location, privateCertificate);
        if (addToTrustedPublisher)
        {
            using X509Certificate2 publicCopy =
                X509CertificateLoader.LoadCertificate(
                    privateCertificate.RawData);
            AddToStore(
                StoreName.TrustedPublisher,
                StoreLocation.LocalMachine,
                publicCopy);
        }

        return Evidence(privateCertificate);
    }

    private static CngKey CreateNonExportableKey(
        string keyName,
        bool machineKey)
    {
        CngKeyCreationParameters parameters = new()
        {
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = machineKey
                ? CngKeyCreationOptions.MachineKey
                : CngKeyCreationOptions.None,
            KeyUsage = CngKeyUsages.Signing,
            Provider =
                CngProvider.MicrosoftSoftwareKeyStorageProvider,
        };
        parameters.Parameters.Add(
            new CngProperty(
                "Length",
                BitConverter.GetBytes(2048),
                CngPropertyOptions.None));
        return CngKey.Create(
            CngAlgorithm.Rsa,
            keyName,
            parameters);
    }

    private static DisposableCertificateEvidence Evidence(
        X509Certificate2 certificate)
    {
        return new DisposableCertificateEvidence(
            certificate.GetCertHashString(
                HashAlgorithmName.SHA1),
            CertificateIdentity.ComputeCertificateSha256(
                certificate),
            CertificateIdentity
                .ComputeSubjectPublicKeyInfoSha256(
                    certificate));
    }

    private static void AddToStore(
        StoreName name,
        StoreLocation location,
        X509Certificate2 certificate)
    {
        using X509Store store = new(name, location);
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
    }

    private static void WriteConfigurationFiles(
        DisposableLabEvidence evidence)
    {
        string gateway = $$"""
            {
              "Format":"ArtifactSigningGatewayConfigurationV2",
              "Mode":"DisposableTest",
              "GatewayServiceSid":"__GATEWAY_SERVICE_SID__",
              "WorkerServiceSid":"__WORKER_SERVICE_SID__",
              "ProfileSetSha256":"__PROFILE_SET_SHA256__",
              "ListenAddress":"__GATEWAY_LISTEN_ADDRESS__",
              "ListenPort":__GATEWAY_LISTEN_PORT__,
              "ServerCertificateThumbprint":"__GATEWAY_TLS_THUMBPRINT__",
              "AuthorizationPolicies":[{
                "ProjectId":"example-endpoint",
                "ProfileId":"ExampleEndpointBundleV1",
                "ProfileVersion":2,
                "SubmitterClient":{"CertificateSha256":"{{evidence.Submitter.CertificateSha256}}","SubjectPublicKeyInfoSha256":"{{evidence.Submitter.SubjectPublicKeyInfoSha256}}"},
                "SubmitterTrust":{"ExpectedSignerSpkiSha256":"{{evidence.Submitter.SubjectPublicKeyInfoSha256}}","RequiredEnhancedKeyUsageOid":"{{ClientAuthenticationEku}}","TrustedRootThumbprints":["{{evidence.RootThumbprint}}"],"ExtraCertificateThumbprints":[],"RevocationPolicy":"DisposableTestNoCheck","UrlRetrievalTimeoutSeconds":1},
                "ApproverClient":{"CertificateSha256":"{{evidence.Approver.CertificateSha256}}","SubjectPublicKeyInfoSha256":"{{evidence.Approver.SubjectPublicKeyInfoSha256}}"},
                "ApproverTrust":{"ExpectedSignerSpkiSha256":"{{evidence.Approver.SubjectPublicKeyInfoSha256}}","RequiredEnhancedKeyUsageOid":"{{ClientAuthenticationEku}}","TrustedRootThumbprints":["{{evidence.RootThumbprint}}"],"ExtraCertificateThumbprints":[],"RevocationPolicy":"DisposableTestNoCheck","UrlRetrievalTimeoutSeconds":1},
                "RequireDistinctSubmitterAndApprover":true
              }],
              "Auditors":[{
                "ProjectId":"example-endpoint",
                "ProfileId":"ExampleEndpointBundleV1",
                "ProfileVersion":2,
                "Client":{"CertificateSha256":"{{evidence.Auditor.CertificateSha256}}","SubjectPublicKeyInfoSha256":"{{evidence.Auditor.SubjectPublicKeyInfoSha256}}"}
              }],
              "ReceiptTrust":{"ExpectedSignerSpkiSha256":"{{evidence.Receipt.SubjectPublicKeyInfoSha256}}","RequiredEnhancedKeyUsageOid":"{{ClientAuthenticationEku}}","TrustedRootThumbprints":["{{evidence.RootThumbprint}}"],"ExtraCertificateThumbprints":[],"RevocationPolicy":"DisposableTestNoCheck","UrlRetrievalTimeoutSeconds":1}
            }
            """;
        string worker = $$"""
            {
              "Format":"ArtifactSigningWorkerConfigurationV2",
              "Mode":"DisposableTest",
              "WorkerServiceSid":"__WORKER_SERVICE_SID__",
              "GatewayServiceSid":"__GATEWAY_SERVICE_SID__",
              "ProfileSetSha256":"__PROFILE_SET_SHA256__",
              "AuthorizationPolicies":[{
                "ProjectId":"example-endpoint",
                "ProfileId":"ExampleEndpointBundleV1",
                "ProfileVersion":2,
                "SubmitterTrust":{"ExpectedSignerSpkiSha256":"{{evidence.Submitter.SubjectPublicKeyInfoSha256}}","RequiredEnhancedKeyUsageOid":"{{ClientAuthenticationEku}}","TrustedRootThumbprints":["{{evidence.RootThumbprint}}"],"ExtraCertificateThumbprints":[],"RevocationPolicy":"DisposableTestNoCheck","UrlRetrievalTimeoutSeconds":1},
                "ApproverTrust":{"ExpectedSignerSpkiSha256":"{{evidence.Approver.SubjectPublicKeyInfoSha256}}","RequiredEnhancedKeyUsageOid":"{{ClientAuthenticationEku}}","TrustedRootThumbprints":["{{evidence.RootThumbprint}}"],"ExtraCertificateThumbprints":[],"RevocationPolicy":"DisposableTestNoCheck","UrlRetrievalTimeoutSeconds":1},
                "RequireDistinctSubmitterAndApprover":true
              }],
              "SigningPolicies":[{
                "SignerPolicyId":"LabAuthenticodeV1",
                "TimestampPolicyId":"DigiCertRfc3161V1",
                "SignToolPath":"__SIGNTOOL_PATH_JSON__",
                "SignToolSha256":"__SIGNTOOL_SHA256__",
                "SignToolFileVersion":"__SIGNTOOL_FILE_VERSION__",
                "SignerCertificateThumbprint":"__AUTHENTICODE_THUMBPRINT__",
                "TimestampUrl":"__TIMESTAMP_URL__",
                "SignToolTimeoutSeconds":120,
                "AuthenticodeRevocationPolicy":"DisposableTestNoCheck"
              }],
              "Receipt":{
                "CertificateThumbprint":"__RECEIPT_THUMBPRINT__",
                "Trust":{"ExpectedSignerSpkiSha256":"{{evidence.Receipt.SubjectPublicKeyInfoSha256}}","RequiredEnhancedKeyUsageOid":"{{ClientAuthenticationEku}}","TrustedRootThumbprints":["{{evidence.RootThumbprint}}"],"ExtraCertificateThumbprints":[],"RevocationPolicy":"DisposableTestNoCheck","UrlRetrievalTimeoutSeconds":1}
              }
            }
            """;
        File.WriteAllText(
            DisposableLabPaths.GatewayTemplate,
            gateway + Environment.NewLine,
            new UTF8Encoding(false));
        File.WriteAllText(
            DisposableLabPaths.WorkerTemplate,
            worker + Environment.NewLine,
            new UTF8Encoding(false));
        WriteCliConfiguration(
            DisposableLabPaths.SubmitterConfiguration,
            evidence.Submitter,
            evidence);
        WriteCliConfiguration(
            DisposableLabPaths.ApproverConfiguration,
            evidence.Approver,
            evidence);
        WriteCliConfiguration(
            DisposableLabPaths.AuditorConfiguration,
            evidence.Auditor,
            evidence);
    }

    private static void WriteCliConfiguration(
        string path,
        DisposableCertificateEvidence identity,
        DisposableLabEvidence evidence)
    {
        object configuration = new
        {
            Format = "ArtifactSigningCliConfigurationV1",
            Mode = "DisposableTest",
            ServiceUri = "https://127.0.0.1:7443/",
            ServerCertificateSha256 =
                evidence.GatewayTls.CertificateSha256,
            ServerSpkiSha256 =
                evidence.GatewayTls.SubjectPublicKeyInfoSha256,
            ClientIdentity = new
            {
                Provider = "WindowsCurrentUserStore",
                CertificatePath = (string?)null,
                PrivateKeyPath = (string?)null,
                PrivateKeyPasswordFile = (string?)null,
                CertificateThumbprint = identity.Thumbprint,
            },
            SubmitterTrust = new
            {
                ExpectedSignerSpkiSha256 =
                    evidence.Submitter.SubjectPublicKeyInfoSha256,
                RequiredEnhancedKeyUsageOid =
                    ClientAuthenticationEku,
                TrustedRootCertificatePaths = new[]
                {
                    DisposableLabPaths.RootCertificate,
                },
                ExtraCertificatePaths = Array.Empty<string>(),
                RevocationPolicy = "DisposableTestNoCheck",
                UrlRetrievalTimeoutSeconds = 1,
            },
            ReceiptTrust = new
            {
                ExpectedSignerSpkiSha256 =
                    evidence.Receipt.SubjectPublicKeyInfoSha256,
                RequiredEnhancedKeyUsageOid =
                    ClientAuthenticationEku,
                TrustedRootCertificatePaths = new[]
                {
                    DisposableLabPaths.RootCertificate,
                },
                ExtraCertificatePaths = Array.Empty<string>(),
                RevocationPolicy = "DisposableTestNoCheck",
                UrlRetrievalTimeoutSeconds = 1,
            },
        };
        File.WriteAllText(
            path,
            JsonSerializer.Serialize(
                configuration,
                DisposableJson.Options) + Environment.NewLine,
            new UTF8Encoding(false));
    }

    private static string FormatWholeSecond(
        DateTimeOffset value)
    {
        return value.ToUniversalTime()
            .ToString(
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                System.Globalization.CultureInfo.InvariantCulture);
    }
}
