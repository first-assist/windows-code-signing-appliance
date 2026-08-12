namespace ArtifactSigning.Profiles;

public sealed record VerifiedAuthenticodeArtifact
{
    public VerifiedAuthenticodeArtifact(
        string role,
        string fileName,
        long size,
        string sha256,
        string signerThumbprint,
        DateTimeOffset timestampedAt)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(fileName);
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentNullException.ThrowIfNull(signerThumbprint);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(size);

        if (!ProfileContractRules.IsSafeIdentifier(role, maximumCharacters: 64))
        {
            throw new ArgumentException(
                "Artifact role must use the safe identifier grammar.",
                nameof(role));
        }

        if (!ProfileContractRules.IsLeafFileName(fileName, maximumCharacters: 128))
        {
            throw new ArgumentException(
                "Artifact filename must be one canonical leaf token.",
                nameof(fileName));
        }

        if (!ProfileContractRules.IsLowerSha256(sha256))
        {
            throw new ArgumentException(
                "Signed artifact digest must be canonical lowercase SHA-256.",
                nameof(sha256));
        }

        if (!ProfileContractRules.IsUpperCertificateThumbprint(signerThumbprint))
        {
            throw new ArgumentException(
                "Signer thumbprint must be canonical uppercase hexadecimal.",
                nameof(signerThumbprint));
        }

        DateTimeOffset universalTimestamp = timestampedAt.ToUniversalTime();
        if (!ProfileContractRules.IsWholeSecond(universalTimestamp))
        {
            throw new ArgumentException(
                "Verified timestamp must have whole-second precision.",
                nameof(timestampedAt));
        }

        Role = role;
        FileName = fileName;
        Size = size;
        Sha256 = sha256;
        SignerThumbprint = signerThumbprint;
        TimestampedAt = universalTimestamp;
    }

    public string Role { get; }

    public string FileName { get; }

    public long Size { get; }

    public string Sha256 { get; }

    public string SignerThumbprint { get; }

    public DateTimeOffset TimestampedAt { get; }
}
