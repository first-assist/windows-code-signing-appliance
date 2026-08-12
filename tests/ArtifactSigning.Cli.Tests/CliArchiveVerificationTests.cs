using System.Formats.Tar;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using ArtifactSigning.TestProfile;
using Xunit;

namespace ArtifactSigning.Cli.Tests;

public sealed class CliArchiveVerificationTests
{
    private const string RequiredEkuOid =
        "1.3.6.1.5.5.7.3.2";
    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 20, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ReviewRequiresTrustedSignatureAndReconstructsDigest()
    {
        using TestCertificateAuthority authority =
            TestCertificateAuthority.Create();
        using TestIdentity submitter =
            TestIdentity.Create(authority);
        using X509Certificate2 root =
            authority.ExportPublicCertificate();
        CmsTrustPolicy trust = Trust(submitter, root);
        ArtifactSigningRequestV1 request = CreateRequest();
        byte[] requestJson =
            ArtifactSigningRequestJsonSerializer.Serialize(
                request);
        byte[] signature = submitter.Sign(
            requestJson,
            detached: true);
        byte[] archive = BuildArchive(
            new Dictionary<string, byte[]>(
                StringComparer.Ordinal)
            {
                ["request.json"] = requestJson,
                ["request.p7s"] = signature,
            });

        CliReviewedRequest reviewed =
            CliArchives.ReadAndVerifyReview(
                archive,
                trust,
                Now);

        Assert.Equal(
            request.RequestId,
            reviewed.Request.RequestId);
        Assert.Equal(
            RequestDigest.ComputeHex(requestJson),
            reviewed.RequestDigest);
        requestJson[^2] = requestJson[^2] is (byte)'}'
            ? (byte)' '
            : (byte)'}';
        byte[] tampered = BuildArchive(
            new Dictionary<string, byte[]>(
                StringComparer.Ordinal)
            {
                ["request.json"] = requestJson,
                ["request.p7s"] = signature,
            });
        Assert.Throws<InvalidDataException>(
            () => CliArchives.ReadAndVerifyReview(
                tampered,
                trust,
                Now));
    }

    [Fact]
    public void ResultVerifierRejectsChangedReturnedArtifact()
    {
        using TestCertificateAuthority authority =
            TestCertificateAuthority.Create();
        using TestIdentity receiptSigner =
            TestIdentity.Create(authority);
        using X509Certificate2 root =
            authority.ExportPublicCertificate();
        CmsTrustPolicy trust = Trust(
            receiptSigner,
            root);
        CliProfileRegistry profiles = new(
            ExampleProfilePackage.CreatePackageSet());
        string valid = WriteResultArchive(
            receiptSigner,
            tamperResult: false);
        string tampered = WriteResultArchive(
            receiptSigner,
            tamperResult: true);
        try
        {
            CliVerifiedResult verified =
                CliResultVerifier.Verify(
                    valid,
                    trust,
                    Now.AddMinutes(1),
                    profiles);

            Assert.Equal(
                ExampleEndpointBundleV1.ProfileId,
                verified.ProfileId);
            Assert.Throws<InvalidDataException>(
                () => CliResultVerifier.Verify(
                    tampered,
                    trust,
                    Now.AddMinutes(1),
                    profiles));
        }
        finally
        {
            File.Delete(valid);
            File.Delete(tampered);
        }
    }

    private static string WriteResultArchive(
        TestIdentity receiptSigner,
        bool tamperResult)
    {
        SigningProfileDescriptor descriptor =
            ExampleEndpointBundleV1.Instance.Descriptor;
        Dictionary<string, byte[]> resultFiles =
            descriptor.Artifacts
                .Where(item => item.Kind is not
                    SigningProfileArtifactKind
                        .JsonBuildEvidence)
                .ToDictionary(
                    item => item.FileName,
                    item => System.Text.Encoding.UTF8
                        .GetBytes(string.Concat(
                            "result-",
                            item.Role)),
                    StringComparer.Ordinal);
        Dictionary<string, ReceiptArtifactV1> unsigned =
            descriptor.Artifacts.ToDictionary(
                item => item.Role,
                item => new ReceiptArtifactV1(
                    item.Role,
                    item.FileName,
                    1,
                    Digest((char)(
                        '1'
                        + descriptor.Artifacts
                            .IndexOf(item)))),
                StringComparer.Ordinal);
        ReceiptArtifactV1[] results = descriptor.Artifacts
            .Where(item => item.Kind is not
                SigningProfileArtifactKind
                    .JsonBuildEvidence)
            .Select(item => new ReceiptArtifactV1(
                item.Role,
                item.FileName,
                resultFiles[item.FileName].LongLength,
                Sha256(resultFiles[item.FileName])))
            .ToArray();
        ReceiptAuthenticodeArtifactV1[] authenticode =
            descriptor.Artifacts
                .Where(item => item.Kind is
                    SigningProfileArtifactKind
                        .PortableExecutable)
                .Select(item =>
                    new ReceiptAuthenticodeArtifactV1(
                        item.Role,
                        item.FileName,
                        unsigned[item.Role].Sha256,
                        Sha256(
                            resultFiles[
                                item.FileName]),
                        new string('A', 40),
                        new string('B', 40),
                        Now))
                .ToArray();
        ArtifactSigningReceiptV1 receipt = new(
            Guid.NewGuid(),
            Digest('a'),
            ExampleEndpointBundleV1.ProjectId,
            ExampleEndpointBundleV1.ProfileId,
            ExampleEndpointBundleV1.ProfileVersion,
            ExampleEndpointBundleV1.SourceRepository,
            new string('c', 40),
            "1.2.3",
            ExampleEndpointBundleV1.SignerPolicyId,
            ExampleEndpointBundleV1.TimestampPolicyId,
            Digest('d'),
            Digest('e'),
            receiptSigner.SubjectPublicKeyInfoSha256,
            unsigned.Values,
            results,
            authenticode,
            "0.7.0",
            Digest('f'),
            1,
            Now);
        byte[] receiptJson =
            ArtifactSigningReceiptJsonSerializer.Serialize(
                receipt);
        Dictionary<string, byte[]> entries = new(
            StringComparer.Ordinal)
        {
            ["signing-receipt.json"] = receiptJson,
            ["signing-receipt.p7s"] =
                receiptSigner.Sign(
                    receiptJson,
                    detached: true),
        };
        foreach ((string name, byte[] content)
                 in resultFiles)
        {
            entries[string.Concat("bundle/", name)] =
                tamperResult
                    && name is
                        ExampleEndpointBundleV1.AgentFileName
                    ? "changed"u8.ToArray()
                    : content;
        }

        string path = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signctl-result-{Guid.NewGuid():N}.tar");
        File.WriteAllBytes(path, BuildArchive(entries));
        return path;
    }

    private static byte[] BuildArchive(
        IReadOnlyDictionary<string, byte[]> entries)
    {
        using MemoryStream archive = new();
        using (TarWriter writer = new(
                   archive,
                   TarEntryFormat.Ustar,
                   leaveOpen: true))
        {
            foreach ((string name, byte[] content)
                     in entries)
            {
                UstarTarEntry entry = new(
                    TarEntryType.RegularFile,
                    name)
                {
                    DataStream = new MemoryStream(
                        content,
                        writable: false),
                    Gid = 0,
                    Uid = 0,
                    GroupName = string.Empty,
                    UserName = string.Empty,
                    Mode =
                        UnixFileMode.UserRead
                        | UnixFileMode.UserWrite,
                    ModificationTime =
                        DateTimeOffset.UnixEpoch,
                };
                writer.WriteEntry(entry);
            }
        }

        return archive.ToArray();
    }

    private static ArtifactSigningRequestV1 CreateRequest()
    {
        return new ArtifactSigningRequestV1(
            Guid.NewGuid(),
            "example-project",
            "ExampleProfileV1",
            1,
            "example/project",
            new string('1', 40),
            "1.0.0",
            Now.AddMinutes(-1),
            Now.AddMinutes(10),
            Convert.ToBase64String(
                    Enumerable.Repeat(
                        (byte)0x44,
                        32).ToArray())
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_'),
            "ExampleSignerV1",
            "ExampleTimestampV1",
            [
                new RequestArtifactV1(
                    "Agent",
                    "agent.exe",
                    1,
                    Digest('2')),
            ]);
    }

    private static CmsTrustPolicy Trust(
        TestIdentity identity,
        X509Certificate2 root)
    {
        return new CmsTrustPolicy(
            identity.SubjectPublicKeyInfoSha256,
            RequiredEkuOid,
            [root],
            CmsRevocationPolicy.DisposableTestNoCheck,
            TimeSpan.FromSeconds(1));
    }

    private static string Sha256(
        ReadOnlySpan<byte> value)
    {
        return Convert.ToHexStringLower(
            SHA256.HashData(value));
    }

    private static string Digest(char value)
    {
        return new string(value, 64);
    }

    private sealed class TestCertificateAuthority :
        IDisposable
    {
        private readonly RSA _key;

        private TestCertificateAuthority(
            RSA key,
            X509Certificate2 certificate)
        {
            _key = key;
            Certificate = certificate;
        }

        internal X509Certificate2 Certificate { get; }

        internal static TestCertificateAuthority Create()
        {
            RSA key = RSA.Create(2048);
            CertificateRequest request = new(
                "CN=Disposable CLI Test Root",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    certificateAuthority: true,
                    hasPathLengthConstraint: true,
                    pathLengthConstraint: 0,
                    critical: true));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.KeyCertSign
                    | X509KeyUsageFlags.CrlSign,
                    critical: true));
            request.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(
                    request.PublicKey,
                    critical: false));
            X509Certificate2 certificate =
                request.CreateSelfSigned(
                    Now.AddDays(-1),
                    Now.AddDays(1));
            return new TestCertificateAuthority(
                key,
                certificate);
        }

        internal X509Certificate2 ExportPublicCertificate()
        {
            return X509CertificateLoader.LoadCertificate(
                Certificate.RawData);
        }

        public void Dispose()
        {
            Certificate.Dispose();
            _key.Dispose();
        }
    }

    private sealed class TestIdentity : IDisposable
    {
        private readonly RSA _key;

        private TestIdentity(
            RSA key,
            X509Certificate2 certificate)
        {
            _key = key;
            Certificate = certificate;
        }

        internal X509Certificate2 Certificate { get; }

        internal string SubjectPublicKeyInfoSha256 =>
            CertificateIdentity
                .ComputeSubjectPublicKeyInfoSha256(
                    Certificate);

        internal static TestIdentity Create(
            TestCertificateAuthority authority)
        {
            RSA key = RSA.Create(2048);
            CertificateRequest request = new(
                "CN=Disposable CLI Test Identity",
                key,
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
            OidCollection usages = new();
            usages.Add(new Oid(RequiredEkuOid));
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    usages,
                    critical: true));
            request.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(
                    request.PublicKey,
                    critical: false));
            using X509Certificate2 publicCertificate =
                request.Create(
                    authority.Certificate,
                    Now.AddDays(-1),
                    Now.AddDays(1),
                    RandomNumberGenerator.GetBytes(16));
            return new TestIdentity(
                key,
                publicCertificate.CopyWithPrivateKey(key));
        }

        internal byte[] Sign(
            ReadOnlySpan<byte> content,
            bool detached)
        {
            return CliCertificateLoader.SignCms(
                content,
                Certificate,
                detached);
        }

        public void Dispose()
        {
            Certificate.Dispose();
            _key.Dispose();
        }
    }
}
