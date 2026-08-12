namespace ArtifactSigning.Windows;

public enum AuthenticodeVerificationError
{
    None,
    PlatformUnsupported,
    ArtifactInvalid,
    ArtifactMismatch,
    ArtifactChanged,
    CatalogInspectionFailed,
    CatalogSignaturePresent,
    EmbeddedSignatureMissing,
    EmbeddedSignaturePresent,
    EmbeddedSignatureInvalid,
    WindowsTrustFailed,
    SignerMismatch,
    SignerChainInvalid,
    SignerDigestAlgorithmInvalid,
    TimestampMissing,
    TimestampInvalid,
    TimestampDigestAlgorithmInvalid,
    TimestampChainInvalid,
    CertificateRevoked,
    RevocationUncertain,
}
