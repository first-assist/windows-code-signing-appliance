using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.Windows;

internal sealed record AuthenticodeCmsEvidence(
    string SignerThumbprint,
    string TimestampAuthorityThumbprint,
    DateTimeOffset TimestampedAt);

internal sealed record AuthenticodeCmsInspectionResult(
    AuthenticodeCmsEvidence? Evidence,
    AuthenticodeVerificationError Error)
{
    internal bool IsSuccess =>
        Error is AuthenticodeVerificationError.None && Evidence is not null;
}

internal enum TimestampTrustError
{
    None,
    Invalid,
    Revoked,
    RevocationUncertain,
}

internal enum SignerTrustError
{
    None,
    Invalid,
    Revoked,
    RevocationUncertain,
}

internal interface ISignerTrustEvaluator
{
    SignerTrustError Evaluate(
        X509Certificate2 signerCertificate,
        X509Certificate2Collection embeddedCertificates,
        DateTimeOffset timestamp,
        AuthenticodeTrustPolicy trustPolicy);
}

internal sealed class SignerTrustEvaluator : ISignerTrustEvaluator
{
    private const string CodeSigningEkuOid = "1.3.6.1.5.5.7.3.3";

    public SignerTrustError Evaluate(
        X509Certificate2 signerCertificate,
        X509Certificate2Collection embeddedCertificates,
        DateTimeOffset timestamp,
        AuthenticodeTrustPolicy trustPolicy)
    {
        try
        {
            using X509Chain chain = new();
            chain.ChainPolicy.RevocationMode = trustPolicy.SignerRevocationPolicy
                is WindowsTrustRevocationPolicy.Online
                    ? X509RevocationMode.Online
                    : X509RevocationMode.NoCheck;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = timestamp.UtcDateTime;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(15);
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(CodeSigningEkuOid));
            foreach (X509Certificate2 certificate in embeddedCertificates)
            {
                if (!certificate.RawDataMemory.Span.SequenceEqual(
                        signerCertificate.RawDataMemory.Span))
                {
                    chain.ChainPolicy.ExtraStore.Add(certificate);
                }
            }

            if (!chain.Build(signerCertificate))
            {
                return MapChainError(chain.ChainStatus);
            }

            X509Certificate2? root = chain.ChainElements.Count > 0
                ? chain.ChainElements[^1].Certificate
                : null;
            return root is not null
                && trustPolicy.TrustedPublisherRootThumbprints.Contains(
                    root.GetCertHashString(HashAlgorithmName.SHA1),
                    StringComparer.Ordinal)
                    ? SignerTrustError.None
                    : SignerTrustError.Invalid;
        }
        catch (CryptographicException)
        {
            return SignerTrustError.Invalid;
        }
    }

    private static SignerTrustError MapChainError(
        IEnumerable<X509ChainStatus> statuses)
    {
        X509ChainStatusFlags combined = statuses.Aggregate(
            X509ChainStatusFlags.NoError,
            (current, status) => current | status.Status);
        if (combined.HasFlag(X509ChainStatusFlags.Revoked))
        {
            return SignerTrustError.Revoked;
        }

        if (combined.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown)
            || combined.HasFlag(X509ChainStatusFlags.OfflineRevocation))
        {
            return SignerTrustError.RevocationUncertain;
        }

        return SignerTrustError.Invalid;
    }
}

internal interface ITimestampTrustEvaluator
{
    TimestampTrustError Evaluate(
        X509Certificate2 timestampCertificate,
        X509Certificate2Collection embeddedCertificates,
        DateTimeOffset timestamp,
        WindowsTrustRevocationPolicy revocationPolicy);
}

internal sealed class TimestampTrustEvaluator : ITimestampTrustEvaluator
{
    private const string TimestampingEkuOid = "1.3.6.1.5.5.7.3.8";

    public TimestampTrustError Evaluate(
        X509Certificate2 timestampCertificate,
        X509Certificate2Collection embeddedCertificates,
        DateTimeOffset timestamp,
        WindowsTrustRevocationPolicy revocationPolicy)
    {
        try
        {
            using X509Chain chain = new();
            chain.ChainPolicy.RevocationMode = MapRevocationMode(revocationPolicy);
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = timestamp.UtcDateTime;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(15);
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(TimestampingEkuOid));
            foreach (X509Certificate2 certificate in embeddedCertificates)
            {
                if (!certificate.RawDataMemory.Span.SequenceEqual(
                        timestampCertificate.RawDataMemory.Span))
                {
                    chain.ChainPolicy.ExtraStore.Add(certificate);
                }
            }

            return chain.Build(timestampCertificate)
                ? TimestampTrustError.None
                : MapChainError(chain.ChainStatus);
        }
        catch (CryptographicException)
        {
            return TimestampTrustError.Invalid;
        }
    }

    private static X509RevocationMode MapRevocationMode(
        WindowsTrustRevocationPolicy policy)
    {
        return policy switch
        {
            WindowsTrustRevocationPolicy.Online => X509RevocationMode.Online,
            WindowsTrustRevocationPolicy.OfflineCache => X509RevocationMode.Offline,
            WindowsTrustRevocationPolicy.DisposableTestNoCheck => X509RevocationMode.NoCheck,
            WindowsTrustRevocationPolicy.RetainedLabPinned => X509RevocationMode.NoCheck,
            _ => throw new ArgumentOutOfRangeException(nameof(policy)),
        };
    }

    private static TimestampTrustError MapChainError(
        IEnumerable<X509ChainStatus> statuses)
    {
        X509ChainStatusFlags combined = statuses.Aggregate(
            X509ChainStatusFlags.NoError,
            (current, status) => current | status.Status);
        if (combined.HasFlag(X509ChainStatusFlags.Revoked))
        {
            return TimestampTrustError.Revoked;
        }

        if (combined.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown)
            || combined.HasFlag(X509ChainStatusFlags.OfflineRevocation))
        {
            return TimestampTrustError.RevocationUncertain;
        }

        return TimestampTrustError.Invalid;
    }
}

internal sealed class AuthenticodeCmsInspector
{
    private const int MaximumEmbeddedCertificates = 16;
    private const int MaximumTimestampTokenBytes = 256 * 1024;
    private const string AuthenticodeContentTypeOid = "1.3.6.1.4.1.311.2.1.4";
    private const string CodeSigningEkuOid = "1.3.6.1.5.5.7.3.3";
    private const string MicrosoftPublicTrustEkuOid =
        "1.3.6.1.4.1.311.97.1.0";
    private const string MicrosoftPublicTrustTestEkuPrefix =
        "1.3.6.1.4.1.311.97.1.2.";
    private const string Rfc3161TimestampAttributeOid = "1.3.6.1.4.1.311.3.3.1";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    private readonly ITimestampTrustEvaluator _timestampTrustEvaluator;
    private readonly ISignerTrustEvaluator _signerTrustEvaluator;

    internal AuthenticodeCmsInspector()
        : this(new TimestampTrustEvaluator())
    {
    }

    internal AuthenticodeCmsInspector(
        ITimestampTrustEvaluator timestampTrustEvaluator)
        : this(timestampTrustEvaluator, new SignerTrustEvaluator())
    {
    }

    internal AuthenticodeCmsInspector(
        ITimestampTrustEvaluator timestampTrustEvaluator,
        ISignerTrustEvaluator signerTrustEvaluator)
    {
        ArgumentNullException.ThrowIfNull(timestampTrustEvaluator);
        ArgumentNullException.ThrowIfNull(signerTrustEvaluator);
        _timestampTrustEvaluator = timestampTrustEvaluator;
        _signerTrustEvaluator = signerTrustEvaluator;
    }

    internal AuthenticodeCmsInspectionResult Inspect(
        ReadOnlyMemory<byte> encodedSignature,
        AuthenticodeTrustPolicy trustPolicy)
    {
        if (encodedSignature.IsEmpty
            || encodedSignature.Length > EmbeddedSignatureReader.MaximumEmbeddedSignatureBytes)
        {
            return Failure(AuthenticodeVerificationError.EmbeddedSignatureInvalid);
        }

        SignedCms signedCms = new();
        try
        {
            signedCms.Decode(encodedSignature.Span);
            signedCms.CheckSignature(verifySignatureOnly: true);
        }
        catch (CryptographicException)
        {
            return Failure(AuthenticodeVerificationError.EmbeddedSignatureInvalid);
        }

        if (!string.Equals(
                signedCms.ContentInfo.ContentType.Value,
                AuthenticodeContentTypeOid,
                StringComparison.Ordinal)
            || signedCms.SignerInfos.Count is not 1
            || signedCms.Certificates.Count is 0 or > MaximumEmbeddedCertificates)
        {
            return Failure(AuthenticodeVerificationError.EmbeddedSignatureInvalid);
        }

        SignerInfo signer = signedCms.SignerInfos[0];
        X509Certificate2? signerCertificate = signer.Certificate;
        if (signerCertificate is null || !HasCodeSigningProfile(signerCertificate))
        {
            return Failure(AuthenticodeVerificationError.EmbeddedSignatureInvalid);
        }

        if (!string.Equals(
                signer.DigestAlgorithm.Value,
                Sha256Oid,
                StringComparison.Ordinal))
        {
            return Failure(
                AuthenticodeVerificationError.SignerDigestAlgorithmInvalid);
        }

        string signerThumbprint =
            signerCertificate.GetCertHashString(HashAlgorithmName.SHA1);
        if (!MatchesSignerIdentity(signerCertificate, signerThumbprint, trustPolicy))
        {
            return Failure(AuthenticodeVerificationError.SignerMismatch);
        }

        CryptographicAttributeObject[] timestampAttributes =
            signer.UnsignedAttributes
                .Cast<CryptographicAttributeObject>()
                .Where(
                    attribute => string.Equals(
                        attribute.Oid?.Value,
                        Rfc3161TimestampAttributeOid,
                        StringComparison.Ordinal))
                .ToArray();
        if (timestampAttributes.Length is 0)
        {
            return Failure(AuthenticodeVerificationError.TimestampMissing);
        }

        if (signer.CounterSignerInfos.Count is not 0
            || signer.UnsignedAttributes.Count is not 1
            || timestampAttributes.Length is not 1
            || timestampAttributes[0].Values.Count is not 1)
        {
            return Failure(AuthenticodeVerificationError.TimestampInvalid);
        }

        byte[] encodedTimestamp = timestampAttributes[0].Values[0].RawData;
        if (encodedTimestamp.Length is 0 or > MaximumTimestampTokenBytes
            || !Rfc3161TimestampToken.TryDecode(
                encodedTimestamp,
                out Rfc3161TimestampToken? timestampToken,
                out int bytesConsumed)
            || timestampToken is null
            || bytesConsumed != encodedTimestamp.Length)
        {
            return Failure(AuthenticodeVerificationError.TimestampInvalid);
        }

        if (!string.Equals(
                timestampToken.TokenInfo.HashAlgorithmId.Value,
                Sha256Oid,
                StringComparison.Ordinal))
        {
            return Failure(
                AuthenticodeVerificationError.TimestampDigestAlgorithmInvalid);
        }

        if (!timestampToken.VerifySignatureForSignerInfo(
                signer,
                out X509Certificate2? timestampCertificate,
                signedCms.Certificates)
            || timestampCertificate is null)
        {
            timestampCertificate?.Dispose();
            return Failure(AuthenticodeVerificationError.TimestampInvalid);
        }

        using (timestampCertificate)
        {
            DateTimeOffset timestamp =
                timestampToken.TokenInfo.Timestamp.ToUniversalTime();
            // RFC 3161 permits fractional seconds. Trust evaluation uses the
            // exact token time; persisted protocol evidence is whole-second UTC.
            DateTimeOffset evidenceTimestamp = new(
                timestamp.Year,
                timestamp.Month,
                timestamp.Day,
                timestamp.Hour,
                timestamp.Minute,
                timestamp.Second,
                TimeSpan.Zero);

            SignedCms timestampCms = timestampToken.AsSignedCms();
            if (timestampCms.SignerInfos.Count is not 1
                || timestampCms.Certificates.Count
                    is 0 or > MaximumEmbeddedCertificates)
            {
                return Failure(AuthenticodeVerificationError.TimestampInvalid);
            }

            TimestampTrustError trustError = _timestampTrustEvaluator.Evaluate(
                timestampCertificate,
                timestampCms.Certificates,
                timestamp,
                trustPolicy.TimestampRevocationPolicy);
            AuthenticodeVerificationError mappedError = MapTimestampTrustError(
                trustError);
            if (mappedError is not AuthenticodeVerificationError.None)
            {
                return Failure(mappedError);
            }

            if (trustPolicy.SignerTrustKind
                is AuthenticodeSignerTrustKind.MicrosoftArtifactSigningPublisher)
            {
                SignerTrustError signerTrustError =
                    _signerTrustEvaluator.Evaluate(
                        signerCertificate,
                        signedCms.Certificates,
                        timestamp,
                        trustPolicy);
                AuthenticodeVerificationError signerError =
                    MapSignerTrustError(signerTrustError);
                if (signerError is not AuthenticodeVerificationError.None)
                {
                    return Failure(signerError);
                }
            }

            return new AuthenticodeCmsInspectionResult(
                new AuthenticodeCmsEvidence(
                    signerThumbprint,
                    timestampCertificate.GetCertHashString(HashAlgorithmName.SHA1),
                    evidenceTimestamp),
                AuthenticodeVerificationError.None);
        }
    }

    private static bool MatchesSignerIdentity(
        X509Certificate2 signerCertificate,
        string signerThumbprint,
        AuthenticodeTrustPolicy trustPolicy)
    {
        if (trustPolicy.SignerTrustKind
            is AuthenticodeSignerTrustKind.ExactCertificate)
        {
            return string.Equals(
                    signerThumbprint,
                    trustPolicy.ExpectedSignerThumbprint,
                    StringComparison.Ordinal)
                && (trustPolicy.ExpectedSignerCertificateSha256 is null
                    || string.Equals(
                        ComputeCertificateSha256(signerCertificate),
                        trustPolicy.ExpectedSignerCertificateSha256,
                        StringComparison.Ordinal))
                && (trustPolicy.ExpectedSignerSubjectPublicKeyInfoSha256 is null
                    || string.Equals(
                        ComputeSubjectPublicKeyInfoSha256(signerCertificate),
                        trustPolicy.ExpectedSignerSubjectPublicKeyInfoSha256,
                        StringComparison.Ordinal));
        }

        if (trustPolicy.SignerTrustKind
            is not AuthenticodeSignerTrustKind.MicrosoftArtifactSigningPublisher
            || !string.Equals(
                ComputeSubjectNameSha256(signerCertificate),
                trustPolicy.ExpectedPublisherSubjectNameSha256,
                StringComparison.Ordinal))
        {
            return false;
        }

        X509EnhancedKeyUsageExtension? enhancedKeyUsages = signerCertificate
            .Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SingleOrDefault();
        if (enhancedKeyUsages is null)
        {
            return false;
        }

        Oid[] ekuOids = enhancedKeyUsages.EnhancedKeyUsages
            .Cast<Oid>()
            .ToArray();
        bool isPublicTrustTest = trustPolicy
            .RequiredPublisherEnhancedKeyUsageOid!
            .StartsWith(
                MicrosoftPublicTrustTestEkuPrefix,
                StringComparison.Ordinal);
        return (isPublicTrustTest || ekuOids.Any(oid =>
                string.Equals(
                    oid.Value,
                    MicrosoftPublicTrustEkuOid,
                    StringComparison.Ordinal)))
            && ekuOids.Any(oid =>
                string.Equals(
                    oid.Value,
                    trustPolicy.RequiredPublisherEnhancedKeyUsageOid,
                    StringComparison.Ordinal));
    }

    private static bool HasCodeSigningProfile(X509Certificate2 certificate)
    {
        X509BasicConstraintsExtension[] basicConstraints = certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .ToArray();
        if (basicConstraints.Length is not 1
            || basicConstraints[0].CertificateAuthority)
        {
            return false;
        }

        X509EnhancedKeyUsageExtension[] enhancedKeyUsages = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .ToArray();
        if (enhancedKeyUsages.Length is not 1
            || !enhancedKeyUsages[0].EnhancedKeyUsages
                .Cast<Oid>()
                .Any(
                    oid => string.Equals(
                        oid.Value,
                        CodeSigningEkuOid,
                        StringComparison.Ordinal)))
        {
            return false;
        }

        X509KeyUsageExtension[] keyUsages = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .ToArray();
        return keyUsages.Length <= 1
            && (keyUsages.Length is 0
                || keyUsages[0].KeyUsages.HasFlag(
                    X509KeyUsageFlags.DigitalSignature));
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

    private static AuthenticodeVerificationError MapSignerTrustError(
        SignerTrustError error)
    {
        return error switch
        {
            SignerTrustError.None => AuthenticodeVerificationError.None,
            SignerTrustError.Invalid =>
                AuthenticodeVerificationError.SignerChainInvalid,
            SignerTrustError.Revoked =>
                AuthenticodeVerificationError.CertificateRevoked,
            SignerTrustError.RevocationUncertain =>
                AuthenticodeVerificationError.RevocationUncertain,
            _ => throw new ArgumentOutOfRangeException(nameof(error)),
        };
    }

    private static AuthenticodeVerificationError MapTimestampTrustError(
        TimestampTrustError error)
    {
        return error switch
        {
            TimestampTrustError.None => AuthenticodeVerificationError.None,
            TimestampTrustError.Invalid =>
                AuthenticodeVerificationError.TimestampChainInvalid,
            TimestampTrustError.Revoked =>
                AuthenticodeVerificationError.CertificateRevoked,
            TimestampTrustError.RevocationUncertain =>
                AuthenticodeVerificationError.RevocationUncertain,
            _ => throw new ArgumentOutOfRangeException(nameof(error)),
        };
    }

    private static AuthenticodeCmsInspectionResult Failure(
        AuthenticodeVerificationError error)
    {
        return new AuthenticodeCmsInspectionResult(null, error);
    }
}
