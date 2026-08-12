namespace ArtifactSigning.Windows;

public sealed class WindowsAuthenticodeFileVerifier : IAuthenticodeFileVerifier
{
    private readonly IWindowsCatalogInspector _catalogInspector;
    private readonly IWindowsNativeTrust _nativeTrust;
    private readonly AuthenticodeCmsInspector _cmsInspector;

    public WindowsAuthenticodeFileVerifier()
        : this(
            new WindowsCatalogInspector(),
            new WindowsNativeTrust(),
            new AuthenticodeCmsInspector())
    {
    }

    internal WindowsAuthenticodeFileVerifier(
        IWindowsCatalogInspector catalogInspector,
        IWindowsNativeTrust nativeTrust,
        AuthenticodeCmsInspector cmsInspector)
    {
        _catalogInspector = catalogInspector;
        _nativeTrust = nativeTrust;
        _cmsInspector = cmsInspector;
    }

    public AuthenticodeVerificationError VerifyUnsigned(
        string trustedAbsolutePath,
        long expectedSize,
        string expectedSha256)
    {
        ValidateExpectedArtifact(expectedSize, expectedSha256);
        if (!OperatingSystem.IsWindows())
        {
            return AuthenticodeVerificationError.PlatformUnsupported;
        }

        try
        {
            using FileStream stream = OpenValidatedFile(trustedAbsolutePath);
            ArtifactFileSnapshot before = ArtifactFileSnapshot.Create(stream);
            if (!before.Matches(expectedSize, expectedSha256))
            {
                return AuthenticodeVerificationError.ArtifactMismatch;
            }

            CatalogSignatureState catalogState = _catalogInspector.Inspect(
                stream.SafeFileHandle);
            if (catalogState is CatalogSignatureState.InspectionFailed)
            {
                return AuthenticodeVerificationError.CatalogInspectionFailed;
            }

            if (catalogState is CatalogSignatureState.Present)
            {
                return AuthenticodeVerificationError.CatalogSignaturePresent;
            }

            EmbeddedSignatureReadResult embeddedSignature =
                EmbeddedSignatureReader.Read(stream);
            if (embeddedSignature.State is EmbeddedSignatureState.Invalid)
            {
                return AuthenticodeVerificationError.ArtifactInvalid;
            }

            if (embeddedSignature.State is EmbeddedSignatureState.Present)
            {
                return AuthenticodeVerificationError.EmbeddedSignaturePresent;
            }

            ArtifactFileSnapshot after = ArtifactFileSnapshot.Create(stream);
            return before == after
                ? AuthenticodeVerificationError.None
                : AuthenticodeVerificationError.ArtifactChanged;
        }
        catch (IOException)
        {
            return AuthenticodeVerificationError.ArtifactInvalid;
        }
        catch (UnauthorizedAccessException)
        {
            return AuthenticodeVerificationError.ArtifactInvalid;
        }
        catch (InvalidDataException)
        {
            return AuthenticodeVerificationError.ArtifactInvalid;
        }
        catch (DllNotFoundException)
        {
            return AuthenticodeVerificationError.PlatformUnsupported;
        }
        catch (EntryPointNotFoundException)
        {
            return AuthenticodeVerificationError.PlatformUnsupported;
        }
    }

    public AuthenticodeVerificationResult VerifySigned(
        string trustedAbsolutePath,
        long expectedSize,
        string expectedSha256,
        AuthenticodeTrustPolicy trustPolicy)
    {
        ArgumentNullException.ThrowIfNull(trustPolicy);
        ValidateExpectedArtifact(expectedSize, expectedSha256);
        if (!OperatingSystem.IsWindows())
        {
            return AuthenticodeVerificationResult.Failure(
                AuthenticodeVerificationError.PlatformUnsupported);
        }

        try
        {
            using FileStream stream = OpenValidatedFile(trustedAbsolutePath);
            ArtifactFileSnapshot before = ArtifactFileSnapshot.Create(stream);
            if (!before.Matches(expectedSize, expectedSha256))
            {
                return AuthenticodeVerificationResult.Failure(
                    AuthenticodeVerificationError.ArtifactMismatch);
            }

            CatalogSignatureState catalogState = _catalogInspector.Inspect(
                stream.SafeFileHandle);
            if (catalogState is CatalogSignatureState.InspectionFailed)
            {
                return AuthenticodeVerificationResult.Failure(
                    AuthenticodeVerificationError.CatalogInspectionFailed);
            }

            if (catalogState is CatalogSignatureState.Present)
            {
                return AuthenticodeVerificationResult.Failure(
                    AuthenticodeVerificationError.CatalogSignaturePresent);
            }

            EmbeddedSignatureReadResult embeddedSignature =
                EmbeddedSignatureReader.Read(stream);
            if (embeddedSignature.State is EmbeddedSignatureState.Missing)
            {
                return AuthenticodeVerificationResult.Failure(
                    AuthenticodeVerificationError.EmbeddedSignatureMissing);
            }

            if (embeddedSignature.State is EmbeddedSignatureState.Invalid
                || embeddedSignature.SignedCms is null)
            {
                return AuthenticodeVerificationResult.Failure(
                    AuthenticodeVerificationError.EmbeddedSignatureInvalid);
            }

            if (_nativeTrust.VerifyEmbeddedSignature(
                    trustedAbsolutePath,
                    stream.SafeFileHandle,
                    trustPolicy.SignerRevocationPolicy)
                is not WindowsTrustStatus.Trusted)
            {
                return AuthenticodeVerificationResult.Failure(
                    AuthenticodeVerificationError.WindowsTrustFailed);
            }

            AuthenticodeCmsInspectionResult cmsResult = _cmsInspector.Inspect(
                embeddedSignature.SignedCms,
                trustPolicy);
            if (!cmsResult.IsSuccess || cmsResult.Evidence is null)
            {
                return AuthenticodeVerificationResult.Failure(cmsResult.Error);
            }

            ArtifactFileSnapshot after = ArtifactFileSnapshot.Create(stream);
            if (before != after)
            {
                return AuthenticodeVerificationResult.Failure(
                    AuthenticodeVerificationError.ArtifactChanged);
            }

            return new AuthenticodeVerificationResult(
                new VerifiedAuthenticodeFile(
                    after.Size,
                    after.Sha256,
                    cmsResult.Evidence.SignerThumbprint,
                    cmsResult.Evidence.TimestampAuthorityThumbprint,
                    cmsResult.Evidence.TimestampedAt),
                AuthenticodeVerificationError.None);
        }
        catch (IOException)
        {
            return AuthenticodeVerificationResult.Failure(
                AuthenticodeVerificationError.ArtifactInvalid);
        }
        catch (UnauthorizedAccessException)
        {
            return AuthenticodeVerificationResult.Failure(
                AuthenticodeVerificationError.ArtifactInvalid);
        }
        catch (InvalidDataException)
        {
            return AuthenticodeVerificationResult.Failure(
                AuthenticodeVerificationError.ArtifactInvalid);
        }
        catch (DllNotFoundException)
        {
            return AuthenticodeVerificationResult.Failure(
                AuthenticodeVerificationError.PlatformUnsupported);
        }
        catch (EntryPointNotFoundException)
        {
            return AuthenticodeVerificationResult.Failure(
                AuthenticodeVerificationError.PlatformUnsupported);
        }
    }

    private static FileStream OpenValidatedFile(string trustedAbsolutePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedAbsolutePath);
        if (!Path.IsPathFullyQualified(trustedAbsolutePath))
        {
            throw new ArgumentException(
                "Worker artifact path must be fully qualified.",
                nameof(trustedAbsolutePath));
        }

        FileAttributes attributes = File.GetAttributes(trustedAbsolutePath);
        if (attributes.HasFlag(FileAttributes.Directory)
            || attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException();
        }

        FileStream stream = new(
            trustedAbsolutePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.RandomAccess);
        if (!WindowsFileHandleInspector.IsDirectSingleLinkFile(
                stream.SafeFileHandle))
        {
            stream.Dispose();
            throw new InvalidDataException();
        }

        return stream;
    }

    private static void ValidateExpectedArtifact(
        long expectedSize,
        string expectedSha256)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(expectedSize);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            expectedSize,
            ArtifactFileSnapshot.MaximumArtifactBytes);
        ArgumentNullException.ThrowIfNull(expectedSha256);
        if (!WindowsContractRules.IsLowerSha256(expectedSha256))
        {
            throw new ArgumentException(
                "Expected artifact digest must be canonical lowercase SHA-256.",
                nameof(expectedSha256));
        }
    }
}
