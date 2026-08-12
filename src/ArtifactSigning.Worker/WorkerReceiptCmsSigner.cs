using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Worker;

public enum WorkerReceiptSigningError
{
    None,
    SigningFailed,
    SignatureTooLarge,
    SelfVerificationFailed,
}

public sealed class WorkerReceiptSigningResult
{
    private readonly byte[]? _signature;

    private WorkerReceiptSigningResult(
        byte[]? signature,
        WorkerReceiptSigningError error)
    {
        _signature = signature;
        Error = error;
    }

    public WorkerReceiptSigningError Error { get; }

    public bool IsSuccess =>
        Error is WorkerReceiptSigningError.None
        && _signature is not null;

    public byte[] GetSignatureBytes()
    {
        if (!IsSuccess)
        {
            throw new InvalidOperationException(
                "A failed receipt signing operation has no signature.");
        }

        return _signature!.ToArray();
    }

    internal static WorkerReceiptSigningResult Success(
        ReadOnlySpan<byte> signature)
    {
        return new WorkerReceiptSigningResult(
            signature.ToArray(),
            WorkerReceiptSigningError.None);
    }

    internal static WorkerReceiptSigningResult Failure(
        WorkerReceiptSigningError error)
    {
        return new WorkerReceiptSigningResult(null, error);
    }
}

public sealed class WorkerReceiptCmsSigner
{
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    private readonly X509Certificate2 _signingCertificate;
    private readonly CmsTrustPolicy _trustPolicy;

    public WorkerReceiptCmsSigner(
        X509Certificate2 signingCertificate,
        CmsTrustPolicy trustPolicy)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(trustPolicy);
        if (!signingCertificate.HasPrivateKey)
        {
            throw new ArgumentException(
                "Receipt signer requires a private key.",
                nameof(signingCertificate));
        }

        string signerSpki =
            CertificateIdentity.ComputeSubjectPublicKeyInfoSha256(
                signingCertificate);
        if (!string.Equals(
                signerSpki,
                trustPolicy.ExpectedSignerSpkiSha256,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Receipt signer does not match its public trust policy.",
                nameof(trustPolicy));
        }

        string thumbprint = signingCertificate.Thumbprint;
        if (!WorkerPolicyRules.IsUpperThumbprint(thumbprint))
        {
            throw new ArgumentException(
                "Receipt signer certificate thumbprint is invalid.",
                nameof(signingCertificate));
        }

        _signingCertificate = signingCertificate;
        _trustPolicy = trustPolicy;
        SubjectPublicKeyInfoSha256 = signerSpki;
        CertificateThumbprint = thumbprint;
    }

    public string SubjectPublicKeyInfoSha256 { get; }

    public string CertificateThumbprint { get; }

    public WorkerReceiptSigningResult SignAndVerify(
        ReadOnlyMemory<byte> receiptJson,
        DateTimeOffset verificationTime)
    {
        if (receiptJson.IsEmpty
            || receiptJson.Length
                > ArtifactSigningReceiptJsonSerializer.MaximumReceiptJsonBytes)
        {
            throw new ArgumentException(
                "Receipt JSON is empty or exceeds the protocol bound.",
                nameof(receiptJson));
        }

        byte[] signature;
        try
        {
            SignedCms signedCms = new(
                new ContentInfo(receiptJson.ToArray()),
                detached: true);
            CmsSigner signer = new(
                SubjectIdentifierType.SubjectKeyIdentifier,
                _signingCertificate)
            {
                DigestAlgorithm = new Oid(Sha256Oid),
                IncludeOption = X509IncludeOption.EndCertOnly,
            };
            signedCms.ComputeSignature(signer, silent: true);
            signature = signedCms.Encode();
        }
        catch (CryptographicException)
        {
            return WorkerReceiptSigningResult.Failure(
                WorkerReceiptSigningError.SigningFailed);
        }

        if (signature.Length
            > DetachedCmsSignatureVerifier.MaximumSignatureBytes)
        {
            return WorkerReceiptSigningResult.Failure(
                WorkerReceiptSigningError.SignatureTooLarge);
        }

        TrustedDetachedCmsVerificationResult verification =
            TrustedDetachedCmsSignatureVerifier.Verify(
                receiptJson,
                signature,
                _trustPolicy,
                verificationTime);
        return verification.IsSuccess
            ? WorkerReceiptSigningResult.Success(signature)
            : WorkerReceiptSigningResult.Failure(
                WorkerReceiptSigningError.SelfVerificationFailed);
    }
}
