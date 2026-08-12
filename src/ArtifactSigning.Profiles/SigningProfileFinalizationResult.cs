namespace ArtifactSigning.Profiles;

public sealed class SigningProfileFinalizationResult
{
    private readonly byte[]? _finalizedManifestBytes;

    private SigningProfileFinalizationResult(
        SigningProfileValidationError error,
        byte[]? finalizedManifestBytes)
    {
        Error = error;
        _finalizedManifestBytes = finalizedManifestBytes;
    }

    public SigningProfileValidationError Error { get; }

    public bool IsSuccess =>
        Error is SigningProfileValidationError.None
        && _finalizedManifestBytes is not null;

    public byte[] GetFinalizedManifestBytes()
    {
        if (!IsSuccess)
        {
            throw new InvalidOperationException(
                "A failed finalization result has no manifest bytes.");
        }

        return _finalizedManifestBytes!.ToArray();
    }

    public static SigningProfileFinalizationResult Success(
        ReadOnlySpan<byte> finalizedManifestBytes)
    {
        if (finalizedManifestBytes.IsEmpty)
        {
            throw new ArgumentException(
                "Finalized manifest bytes cannot be empty.",
                nameof(finalizedManifestBytes));
        }

        return new SigningProfileFinalizationResult(
            SigningProfileValidationError.None,
            finalizedManifestBytes.ToArray());
    }

    public static SigningProfileFinalizationResult Failure(
        SigningProfileValidationError error)
    {
        if (error is SigningProfileValidationError.None || !Enum.IsDefined(error))
        {
            throw new ArgumentOutOfRangeException(nameof(error));
        }

        return new SigningProfileFinalizationResult(error, null);
    }
}
