namespace ArtifactSigning.Windows;

public sealed record VerifiedAuthenticodeFile
{
    internal VerifiedAuthenticodeFile(
        long size,
        string sha256,
        string signerThumbprint,
        string timestampAuthorityThumbprint,
        DateTimeOffset timestampedAt)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(size);
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentNullException.ThrowIfNull(signerThumbprint);
        ArgumentNullException.ThrowIfNull(timestampAuthorityThumbprint);
        if (!WindowsContractRules.IsLowerSha256(sha256))
        {
            throw new ArgumentException(
                "Verified digest must be canonical lowercase SHA-256.",
                nameof(sha256));
        }

        if (!WindowsContractRules.IsUpperCertificateThumbprint(signerThumbprint))
        {
            throw new ArgumentException(
                "Verified signer thumbprint must be canonical uppercase hexadecimal.",
                nameof(signerThumbprint));
        }

        if (!WindowsContractRules.IsUpperCertificateThumbprint(
                timestampAuthorityThumbprint))
        {
            throw new ArgumentException(
                "Timestamp authority thumbprint must be canonical uppercase hexadecimal.",
                nameof(timestampAuthorityThumbprint));
        }

        DateTimeOffset universalTimestamp = timestampedAt.ToUniversalTime();
        if (universalTimestamp.Ticks % TimeSpan.TicksPerSecond is not 0)
        {
            throw new ArgumentException(
                "Verified timestamp must have whole-second precision.",
                nameof(timestampedAt));
        }

        Size = size;
        Sha256 = sha256;
        SignerThumbprint = signerThumbprint;
        TimestampAuthorityThumbprint = timestampAuthorityThumbprint;
        TimestampedAt = universalTimestamp;
    }

    public long Size { get; }

    public string Sha256 { get; }

    public string SignerThumbprint { get; }

    public string TimestampAuthorityThumbprint { get; }

    public DateTimeOffset TimestampedAt { get; }
}
