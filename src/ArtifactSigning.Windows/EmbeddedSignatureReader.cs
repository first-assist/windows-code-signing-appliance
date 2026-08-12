using System.Buffers.Binary;

namespace ArtifactSigning.Windows;

internal enum EmbeddedSignatureState
{
    Invalid,
    Missing,
    Present,
}

internal sealed record EmbeddedSignatureReadResult(
    EmbeddedSignatureState State,
    byte[]? SignedCms);

internal static class EmbeddedSignatureReader
{
    internal const int MaximumEmbeddedSignatureBytes = 1024 * 1024;

    private const ushort Pe32Magic = 0x010b;
    private const ushort Pe32PlusMagic = 0x020b;
    private const ushort WinCertificateRevision20 = 0x0200;
    private const ushort WinCertificatePkcsSignedData = 0x0002;
    private const int SecurityDirectoryIndex = 4;

    internal static EmbeddedSignatureReadResult Read(string trustedAbsolutePath)
    {
        try
        {
            using FileStream stream = new(
                trustedAbsolutePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.RandomAccess);
            return Read(stream);
        }
        catch (IOException)
        {
            return Invalid();
        }
        catch (UnauthorizedAccessException)
        {
            return Invalid();
        }
    }

    internal static EmbeddedSignatureReadResult Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek)
        {
            return Invalid();
        }

        try
        {
            long fileLength = stream.Length;
            if (fileLength is < 256 or > ArtifactFileSnapshot.MaximumArtifactBytes
                || ReadUInt16(stream, 0) is not 0x5a4d)
            {
                return Invalid();
            }

            uint peOffset = ReadUInt32(stream, 0x3c);
            if (peOffset < 64
                || !ReadBytes(stream, peOffset, 4).AsSpan().SequenceEqual("PE\0\0"u8))
            {
                return Invalid();
            }

            long coffOffset = checked(peOffset + 4);
            ushort optionalHeaderSize = ReadUInt16(stream, coffOffset + 16);
            long optionalOffset = checked(coffOffset + 20);
            ushort magic = ReadUInt16(stream, optionalOffset);
            int directoryOffset = magic switch
            {
                Pe32Magic => 96,
                Pe32PlusMagic => 112,
                _ => 0,
            };
            int minimumOptionalSize = checked(
                directoryOffset + ((SecurityDirectoryIndex + 1) * 8));
            if (directoryOffset is 0 || optionalHeaderSize < minimumOptionalSize)
            {
                return Invalid();
            }

            long securityDirectoryOffset = checked(
                optionalOffset + directoryOffset + (SecurityDirectoryIndex * 8L));
            uint certificateOffset = ReadUInt32(stream, securityDirectoryOffset);
            uint certificateSize = ReadUInt32(stream, securityDirectoryOffset + 4);
            if (certificateOffset is 0 && certificateSize is 0)
            {
                return new EmbeddedSignatureReadResult(
                    EmbeddedSignatureState.Missing,
                    null);
            }

            if (certificateOffset is 0 || certificateSize is 0)
            {
                return Invalid();
            }

            long certificateEnd = checked((long)certificateOffset + certificateSize);
            if (certificateOffset % 8 is not 0
                || certificateSize < 8
                || certificateEnd != fileLength)
            {
                return Invalid();
            }

            uint entryLength = ReadUInt32(stream, certificateOffset);
            ushort revision = ReadUInt16(stream, certificateOffset + 4);
            ushort certificateType = ReadUInt16(stream, certificateOffset + 6);
            long alignedEntryEnd = Align8(checked((long)certificateOffset + entryLength));
            if (entryLength <= 8
                || revision is not WinCertificateRevision20
                || certificateType is not WinCertificatePkcsSignedData
                || alignedEntryEnd != certificateEnd)
            {
                return Invalid();
            }

            int cmsLength = checked((int)entryLength - 8);
            if (cmsLength > MaximumEmbeddedSignatureBytes)
            {
                return Invalid();
            }

            byte[] signedCms = ReadBytes(stream, certificateOffset + 8, cmsLength);
            int paddingLength = checked((int)(certificateSize - entryLength));
            if (paddingLength > 0
                && ReadBytes(
                        stream,
                        certificateOffset + entryLength,
                        paddingLength)
                    .Any(value => value is not 0))
            {
                return Invalid();
            }

            return new EmbeddedSignatureReadResult(
                EmbeddedSignatureState.Present,
                signedCms);
        }
        catch (EndOfStreamException)
        {
            return Invalid();
        }
        catch (IOException)
        {
            return Invalid();
        }
        catch (OverflowException)
        {
            return Invalid();
        }
        catch (ArgumentOutOfRangeException)
        {
            return Invalid();
        }
    }

    private static ushort ReadUInt16(Stream stream, long offset)
    {
        return BinaryPrimitives.ReadUInt16LittleEndian(ReadBytes(stream, offset, 2));
    }

    private static uint ReadUInt32(Stream stream, long offset)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(ReadBytes(stream, offset, 4));
    }

    private static byte[] ReadBytes(Stream stream, long offset, int count)
    {
        if (offset < 0 || count < 0 || checked(offset + count) > stream.Length)
        {
            throw new EndOfStreamException();
        }

        byte[] buffer = new byte[count];
        stream.Position = offset;
        stream.ReadExactly(buffer);
        return buffer;
    }

    private static long Align8(long value)
    {
        return checked((value + 7) & ~7L);
    }

    private static EmbeddedSignatureReadResult Invalid()
    {
        return new EmbeddedSignatureReadResult(EmbeddedSignatureState.Invalid, null);
    }
}
