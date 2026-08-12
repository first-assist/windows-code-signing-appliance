using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace ArtifactSigning.Windows.Tests;

public sealed class AuthenticodeCmsInspectorTests
{
    private const string AuthenticodeContentTypeOid = "1.3.6.1.4.1.311.2.1.4";
    private const string CodeSigningEkuOid = "1.3.6.1.5.5.7.3.3";
    private const string TimestampingEkuOid = "1.3.6.1.5.5.7.3.8";
    private const string MicrosoftPublicTrustEkuOid =
        "1.3.6.1.4.1.311.97.1.0";
    private const string MicrosoftSubscriberEkuOid =
        "1.3.6.1.4.1.311.97.102758219.576488180.915968236.896939699";
    private const string MicrosoftPublicTrustTestSubscriberEkuOid =
        "1.3.6.1.4.1.311.97.1.2.102758219.576488180.915968236.896939699";
    private const string Rfc3161TimestampAttributeOid = "1.3.6.1.4.1.311.3.3.1";
    private const string Rfc3161ContentTypeOid = "1.2.840.113549.1.9.16.1.4";
    private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";
    private const string Sha1Oid = "1.3.14.3.2.26";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    private static readonly DateTimeOffset Timestamp = DateTimeOffset.Parse(
        "2026-07-29T10:00:00Z",
        System.Globalization.CultureInfo.InvariantCulture);

    [Fact]
    public void AcceptsOneExactSha256SignerAndRfc3161Timestamp()
    {
        using TestCms message = TestCms.Create();
        RecordingTimestampTrustEvaluator evaluator = new(TimestampTrustError.None);
        AuthenticodeCmsInspector inspector = new(evaluator);

        AuthenticodeCmsInspectionResult result = inspector.Inspect(
            message.Encoded,
            message.CreatePolicy());

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Evidence);
        Assert.Equal(message.SignerThumbprint, result.Evidence.SignerThumbprint);
        Assert.Equal(
            message.TimestampAuthorityThumbprint,
            result.Evidence.TimestampAuthorityThumbprint);
        Assert.Equal(Timestamp, result.Evidence.TimestampedAt);
        Assert.Equal(Timestamp, evaluator.Timestamp);
        Assert.Equal(
            WindowsTrustRevocationPolicy.Online,
            evaluator.RevocationPolicy);
    }

    [Fact]
    public void AcceptsFractionalRfc3161TimestampAndCanonicalizesEvidence()
    {
        DateTimeOffset fractionalTimestamp = Timestamp.AddTicks(3_459_999);
        using TestCms message = TestCms.Create(
            includeMicrosoftPublisherEkus: true,
            timestamp: fractionalTimestamp);
        RecordingTimestampTrustEvaluator timestampEvaluator = new(
            TimestampTrustError.None);
        RecordingSignerTrustEvaluator signerEvaluator = new(
            SignerTrustError.None);
        AuthenticodeCmsInspector inspector = new(
            timestampEvaluator,
            signerEvaluator);

        AuthenticodeCmsInspectionResult result = inspector.Inspect(
            message.Encoded,
            message.CreateMicrosoftPublisherPolicy());

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Evidence);
        Assert.Equal(fractionalTimestamp, timestampEvaluator.Timestamp);
        Assert.Equal(fractionalTimestamp, signerEvaluator.Timestamp);
        Assert.Equal(Timestamp, result.Evidence.TimestampedAt);
    }

    [Fact]
    public void RejectsMissingTimestamp()
    {
        using TestCms message = TestCms.Create(includeTimestamp: false);

        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            message.CreatePolicy());

        Assert.Equal(
            AuthenticodeVerificationError.TimestampMissing,
            result.Error);
    }

    [Fact]
    public void RejectsWrongSigner()
    {
        using TestCms message = TestCms.Create();
        AuthenticodeTrustPolicy wrongPolicy = new(
            new string('A', 40),
            WindowsTrustRevocationPolicy.Online);

        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            wrongPolicy);

        Assert.Equal(
            AuthenticodeVerificationError.SignerMismatch,
            result.Error);
    }

    [Fact]
    public void AcceptsRotatingMicrosoftLeafByStablePublisherIdentity()
    {
        using TestCms message = TestCms.Create(
            includeMicrosoftPublisherEkus: true);
        RecordingSignerTrustEvaluator signerEvaluator = new(
            SignerTrustError.None);
        AuthenticodeCmsInspector inspector = new(
            new RecordingTimestampTrustEvaluator(TimestampTrustError.None),
            signerEvaluator);

        AuthenticodeCmsInspectionResult result = inspector.Inspect(
            message.Encoded,
            message.CreateMicrosoftPublisherPolicy());

        Assert.True(result.IsSuccess);
        Assert.Equal(Timestamp, signerEvaluator.Timestamp);
        Assert.Equal(
            AuthenticodeSignerTrustKind.MicrosoftArtifactSigningPublisher,
            signerEvaluator.Policy?.SignerTrustKind);
    }

    [Fact]
    public void AcceptsPublicTrustTestLeafByTestSubscriberIdentity()
    {
        using TestCms message = TestCms.Create(
            includeMicrosoftPublisherEkus: true,
            includeMicrosoftPublicTrustMarker: false,
            microsoftSubscriberEkuOid:
                MicrosoftPublicTrustTestSubscriberEkuOid);
        RecordingSignerTrustEvaluator signerEvaluator = new(
            SignerTrustError.None);
        AuthenticodeCmsInspector inspector = new(
            new RecordingTimestampTrustEvaluator(TimestampTrustError.None),
            signerEvaluator);

        AuthenticodeCmsInspectionResult result = inspector.Inspect(
            message.Encoded,
            message.CreateMicrosoftPublisherPolicy(
                MicrosoftPublicTrustTestSubscriberEkuOid));

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void PublicTrustTestLeafDoesNotSatisfyProductionPublisherPolicy()
    {
        using TestCms message = TestCms.Create(
            includeMicrosoftPublisherEkus: true,
            includeMicrosoftPublicTrustMarker: false,
            microsoftSubscriberEkuOid:
                MicrosoftPublicTrustTestSubscriberEkuOid);

        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            message.CreateMicrosoftPublisherPolicy());

        Assert.Equal(AuthenticodeVerificationError.SignerMismatch, result.Error);
    }

    [Fact]
    public void ProductionLeafDoesNotSatisfyPublicTrustTestPublisherPolicy()
    {
        using TestCms message = TestCms.Create(
            includeMicrosoftPublisherEkus: true);

        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            message.CreateMicrosoftPublisherPolicy(
                MicrosoftPublicTrustTestSubscriberEkuOid));

        Assert.Equal(AuthenticodeVerificationError.SignerMismatch, result.Error);
    }

    [Fact]
    public void MicrosoftPublisherRejectsLeafWithoutStableEkus()
    {
        using TestCms message = TestCms.Create();
        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            message.CreateMicrosoftPublisherPolicy());

        Assert.Equal(AuthenticodeVerificationError.SignerMismatch, result.Error);
    }

    [Fact]
    public void MicrosoftPublisherRejectsDifferentSubject()
    {
        using TestCms message = TestCms.Create(
            includeMicrosoftPublisherEkus: true);
        AuthenticodeTrustPolicy policy = AuthenticodeTrustPolicy
            .CreateMicrosoftArtifactSigningPublisher(
                new string('a', 64),
                MicrosoftSubscriberEkuOid,
                [new string('A', 40)],
                WindowsTrustRevocationPolicy.Online,
                WindowsTrustRevocationPolicy.Online);

        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            policy);

        Assert.Equal(AuthenticodeVerificationError.SignerMismatch, result.Error);
    }

    [Fact]
    public void RetainedLabRejectsReissuedSignerWithSameKey()
    {
        using TestCms message = TestCms.Create();
        using X509Certificate2 reissued = message.CreateReissuedSigner();
        AuthenticodeTrustPolicy policy = new(
            message.SignerThumbprint,
            WindowsTrustRevocationPolicy.RetainedLabPinned,
            WindowsTrustRevocationPolicy.Online,
            ComputeCertificateSha256(reissued),
            ComputeSubjectPublicKeyInfoSha256(reissued));

        Assert.Equal(
            ComputeSubjectPublicKeyInfoSha256(reissued),
            message.SignerSubjectPublicKeyInfoSha256);

        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            policy);

        Assert.Equal(AuthenticodeVerificationError.SignerMismatch, result.Error);
    }

    [Fact]
    public void RetainedLabUsesOnlineTimestampValidation()
    {
        using TestCms message = TestCms.Create();
        RecordingTimestampTrustEvaluator evaluator = new(TimestampTrustError.None);
        AuthenticodeCmsInspector inspector = new(evaluator);
        AuthenticodeTrustPolicy policy = new(
            message.SignerThumbprint,
            WindowsTrustRevocationPolicy.RetainedLabPinned,
            WindowsTrustRevocationPolicy.Online,
            message.SignerCertificateSha256,
            message.SignerSubjectPublicKeyInfoSha256);

        AuthenticodeCmsInspectionResult result = inspector.Inspect(
            message.Encoded,
            policy);

        Assert.True(result.IsSuccess);
        Assert.Equal(WindowsTrustRevocationPolicy.Online, evaluator.RevocationPolicy);
    }

    [Fact]
    public void RejectsSha1CodeSignerDigest()
    {
        using TestCms message = TestCms.Create(signerDigestOid: Sha1Oid);

        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            message.CreatePolicy());

        Assert.Equal(
            AuthenticodeVerificationError.SignerDigestAlgorithmInvalid,
            result.Error);
    }

    [Fact]
    public void RejectsSha1TimestampDigest()
    {
        using TestCms message = TestCms.Create(timestampDigestOid: Sha1Oid);

        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            message.CreatePolicy());

        Assert.Equal(
            AuthenticodeVerificationError.TimestampDigestAlgorithmInvalid,
            result.Error);
    }

    [Fact]
    public void RejectsMalformedTimestampToken()
    {
        using TestCms message = TestCms.Create(corruptTimestamp: true);

        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            message.CreatePolicy());

        Assert.Equal(
            AuthenticodeVerificationError.TimestampInvalid,
            result.Error);
    }

    [Fact]
    public void RejectsAdditionalUnsignedAttribute()
    {
        using TestCms message = TestCms.Create(addUnknownUnsignedAttribute: true);

        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            message.CreatePolicy());

        Assert.Equal(
            AuthenticodeVerificationError.TimestampInvalid,
            result.Error);
    }

    [Fact]
    public void RejectsCodeSignerWithoutClosedCertificateProfile()
    {
        using TestCms message = TestCms.Create(codeSigningProfile: false);

        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            message.Encoded,
            message.CreatePolicy());

        Assert.Equal(
            AuthenticodeVerificationError.EmbeddedSignatureInvalid,
            result.Error);
    }

    [Theory]
    [InlineData(
        (int)TimestampTrustError.Invalid,
        AuthenticodeVerificationError.TimestampChainInvalid)]
    [InlineData(
        (int)TimestampTrustError.Revoked,
        AuthenticodeVerificationError.CertificateRevoked)]
    [InlineData(
        (int)TimestampTrustError.RevocationUncertain,
        AuthenticodeVerificationError.RevocationUncertain)]
    public void MapsTimestampTrustFailureToBoundedResult(
        int trustErrorValue,
        AuthenticodeVerificationError expectedError)
    {
        using TestCms message = TestCms.Create();
        TimestampTrustError trustError = (TimestampTrustError)trustErrorValue;
        AuthenticodeCmsInspector inspector = new(
            new RecordingTimestampTrustEvaluator(trustError));

        AuthenticodeCmsInspectionResult result = inspector.Inspect(
            message.Encoded,
            message.CreatePolicy());

        Assert.Equal(expectedError, result.Error);
        Assert.Null(result.Evidence);
    }

    [Fact]
    public void RejectsMalformedOuterCms()
    {
        AuthenticodeCmsInspectionResult result = CreateInspector().Inspect(
            new byte[] { 0x30, 0x01, 0x00 },
            new AuthenticodeTrustPolicy(
                new string('A', 40),
                WindowsTrustRevocationPolicy.Online));

        Assert.Equal(
            AuthenticodeVerificationError.EmbeddedSignatureInvalid,
            result.Error);
    }

    private static AuthenticodeCmsInspector CreateInspector()
    {
        return new AuthenticodeCmsInspector(
            new RecordingTimestampTrustEvaluator(TimestampTrustError.None));
    }

    private static string ComputeCertificateSha256(
        X509Certificate2 certificate)
    {
        return Convert.ToHexStringLower(SHA256.HashData(certificate.RawData));
    }

    private static string ComputeSubjectPublicKeyInfoSha256(
        X509Certificate2 certificate)
    {
        return Convert.ToHexStringLower(
            SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()));
    }

    private static string ComputeSubjectNameSha256(
        X509Certificate2 certificate)
    {
        return Convert.ToHexStringLower(
            SHA256.HashData(certificate.SubjectName.RawData));
    }

    private sealed class RecordingTimestampTrustEvaluator(
        TimestampTrustError result) : ITimestampTrustEvaluator
    {
        internal DateTimeOffset Timestamp { get; private set; }

        internal WindowsTrustRevocationPolicy RevocationPolicy { get; private set; }

        public TimestampTrustError Evaluate(
            X509Certificate2 timestampCertificate,
            X509Certificate2Collection embeddedCertificates,
            DateTimeOffset timestamp,
            WindowsTrustRevocationPolicy revocationPolicy)
        {
            Assert.NotNull(timestampCertificate);
            Assert.NotEmpty(embeddedCertificates);
            Timestamp = timestamp;
            RevocationPolicy = revocationPolicy;
            return result;
        }
    }

    private sealed class RecordingSignerTrustEvaluator(
        SignerTrustError result) : ISignerTrustEvaluator
    {
        internal DateTimeOffset Timestamp { get; private set; }

        internal AuthenticodeTrustPolicy? Policy { get; private set; }

        public SignerTrustError Evaluate(
            X509Certificate2 signerCertificate,
            X509Certificate2Collection embeddedCertificates,
            DateTimeOffset timestamp,
            AuthenticodeTrustPolicy trustPolicy)
        {
            Assert.NotNull(signerCertificate);
            Assert.NotEmpty(embeddedCertificates);
            Timestamp = timestamp;
            Policy = trustPolicy;
            return result;
        }
    }

    private sealed class TestCms : IDisposable
    {
        private readonly X509Certificate2 _signerCertificate;
        private readonly X509Certificate2 _timestampCertificate;

        private TestCms(
            byte[] encoded,
            X509Certificate2 signerCertificate,
            X509Certificate2 timestampCertificate)
        {
            Encoded = encoded;
            _signerCertificate = signerCertificate;
            _timestampCertificate = timestampCertificate;
        }

        internal byte[] Encoded { get; }

        internal string SignerThumbprint =>
            _signerCertificate.GetCertHashString(HashAlgorithmName.SHA1);

        internal string TimestampAuthorityThumbprint =>
            _timestampCertificate.GetCertHashString(HashAlgorithmName.SHA1);

        internal string SignerCertificateSha256 =>
            ComputeCertificateSha256(_signerCertificate);

        internal string SignerSubjectPublicKeyInfoSha256 =>
            ComputeSubjectPublicKeyInfoSha256(
                _signerCertificate);

        internal X509Certificate2 CreateReissuedSigner()
        {
            using RSA? key = _signerCertificate.GetRSAPrivateKey();
            Assert.NotNull(key);
            CertificateRequest request = new(
                "CN=Reissued Disposable Authenticode Test",
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
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid(CodeSigningEkuOid) },
                    critical: true));
            return request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(1));
        }

        internal static TestCms Create(
            bool includeTimestamp = true,
            bool codeSigningProfile = true,
            string signerDigestOid = Sha256Oid,
            string timestampDigestOid = Sha256Oid,
            bool corruptTimestamp = false,
            bool addUnknownUnsignedAttribute = false,
            bool includeMicrosoftPublisherEkus = false,
            bool includeMicrosoftPublicTrustMarker = true,
            string microsoftSubscriberEkuOid = MicrosoftSubscriberEkuOid,
            DateTimeOffset? timestamp = null)
        {
            List<string>? signerEkuList = codeSigningProfile
                ? [CodeSigningEkuOid]
                : null;
            if (includeMicrosoftPublisherEkus)
            {
                if (includeMicrosoftPublicTrustMarker)
                {
                    signerEkuList!.Add(MicrosoftPublicTrustEkuOid);
                }

                signerEkuList!.Add(microsoftSubscriberEkuOid);
            }

            string[]? signerEkus = signerEkuList?.ToArray();
            X509Certificate2 signerCertificate = CreateCertificate(
                "CN=Disposable Authenticode Test",
                signerEkus);
            X509Certificate2 timestampCertificate = CreateCertificate(
                "CN=Disposable Timestamp Test",
                [TimestampingEkuOid]);
            try
            {
                SignedCms authenticode = new(
                    new ContentInfo(
                        new Oid(AuthenticodeContentTypeOid),
                        [0x30, 0x00]),
                    detached: false);
                CmsSigner signer = new(
                    SubjectIdentifierType.IssuerAndSerialNumber,
                    signerCertificate)
                {
                    DigestAlgorithm = new Oid(signerDigestOid),
                    IncludeOption = X509IncludeOption.EndCertOnly,
                };
                authenticode.ComputeSignature(signer, silent: true);

                if (includeTimestamp)
                {
                    byte[] encodedTimestamp = CreateTimestampToken(
                        authenticode.SignerInfos[0],
                        timestampCertificate,
                        timestampDigestOid,
                        timestamp ?? Timestamp);
                    if (corruptTimestamp)
                    {
                        encodedTimestamp[^1] ^= 0xff;
                    }

                    authenticode.SignerInfos[0].AddUnsignedAttribute(
                        new Pkcs9AttributeObject(
                            new Oid(Rfc3161TimestampAttributeOid),
                            encodedTimestamp));
                }

                if (addUnknownUnsignedAttribute)
                {
                    authenticode.SignerInfos[0].AddUnsignedAttribute(
                        new Pkcs9AttributeObject(
                            new Oid("1.3.6.1.4.1.311.9999.2"),
                            [0x05, 0x00]));
                }

                return new TestCms(
                    authenticode.Encode(),
                    signerCertificate,
                    timestampCertificate);
            }
            catch
            {
                signerCertificate.Dispose();
                timestampCertificate.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            _signerCertificate.Dispose();
            _timestampCertificate.Dispose();
        }

        internal AuthenticodeTrustPolicy CreatePolicy()
        {
            return new AuthenticodeTrustPolicy(
                SignerThumbprint,
                WindowsTrustRevocationPolicy.Online);
        }

        internal AuthenticodeTrustPolicy CreateMicrosoftPublisherPolicy(
            string subscriberEkuOid = MicrosoftSubscriberEkuOid)
        {
            return AuthenticodeTrustPolicy
                .CreateMicrosoftArtifactSigningPublisher(
                    ComputeSubjectNameSha256(_signerCertificate),
                    subscriberEkuOid,
                    [new string('A', 40)],
                    WindowsTrustRevocationPolicy.Online,
                    WindowsTrustRevocationPolicy.Online);
        }

        private static byte[] CreateTimestampToken(
            SignerInfo signer,
            X509Certificate2 timestampCertificate,
            string timestampDigestOid,
            DateTimeOffset timestamp)
        {
            byte[] signatureHash = HashData(
                signer.GetSignature(),
                timestampDigestOid);
            Rfc3161TimestampTokenInfo tokenInfo = new(
                new Oid("1.3.6.1.4.1.311.9999.1"),
                new Oid(timestampDigestOid),
                signatureHash,
                new byte[] { 1 },
                timestamp,
                accuracyInMicroseconds: null,
                isOrdering: false,
                nonce: null,
                timestampAuthorityName: null,
                extensions: null);
            SignedCms timestampCms = new(
                new ContentInfo(
                    new Oid(Rfc3161ContentTypeOid),
                    tokenInfo.Encode()),
                detached: false);
            CmsSigner timestampSigner = new(
                SubjectIdentifierType.IssuerAndSerialNumber,
                timestampCertificate)
            {
                DigestAlgorithm = new Oid(Sha256Oid),
                IncludeOption = X509IncludeOption.EndCertOnly,
            };
            timestampSigner.SignedAttributes.Add(
                new Pkcs9AttributeObject(
                    new Oid(SigningCertificateV2Oid),
                    EncodeSigningCertificateV2(timestampCertificate)));
            timestampCms.ComputeSignature(timestampSigner, silent: true);
            return timestampCms.Encode();
        }

        private static X509Certificate2 CreateCertificate(
            string subject,
            IEnumerable<string>? enhancedKeyUsageOids)
        {
            RSA key = RSA.Create(2048);
            CertificateRequest request = new(
                subject,
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            if (enhancedKeyUsageOids is not null)
            {
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
                OidCollection enhancedKeyUsages = new();
                foreach (string oid in enhancedKeyUsageOids)
                {
                    enhancedKeyUsages.Add(new Oid(oid));
                }
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        enhancedKeyUsages,
                        critical: true));
            }

            X509Certificate2 certificate = request.CreateSelfSigned(
                Timestamp.AddDays(-1),
                Timestamp.AddDays(1));
            key.Dispose();
            return certificate;
        }

        private static byte[] EncodeSigningCertificateV2(
            X509Certificate2 timestampCertificate)
        {
            AsnWriter writer = new(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    using (writer.PushSequence())
                    {
                        writer.WriteOctetString(
                            SHA256.HashData(timestampCertificate.RawData));
                    }
                }
            }

            return writer.Encode();
        }

        private static byte[] HashData(byte[] value, string algorithmOid)
        {
            return algorithmOid switch
            {
                Sha256Oid => SHA256.HashData(value),
                // The parser rejects SHA-1 before it verifies the imprint.
                Sha1Oid => new byte[20],
                _ => throw new ArgumentOutOfRangeException(nameof(algorithmOid)),
            };
        }
    }
}
