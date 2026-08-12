using System.Buffers.Binary;
using Xunit;

namespace ArtifactSigning.Windows.Tests;

public sealed class EmbeddedSignatureReaderTests
{
    [Fact]
    public void RecognizesUnsignedPortableExecutable()
    {
        using MemoryStream stream = new(CreatePortableExecutable());

        EmbeddedSignatureReadResult result = EmbeddedSignatureReader.Read(stream);

        Assert.Equal(EmbeddedSignatureState.Missing, result.State);
        Assert.Null(result.SignedCms);
    }

    [Fact]
    public void ReadsOneExactPkcsSignedDataEntry()
    {
        byte[] encodedCms = [0x30, 0x03, 0x02, 0x01, 0x01];
        using MemoryStream stream = new(CreatePortableExecutable(encodedCms));

        EmbeddedSignatureReadResult result = EmbeddedSignatureReader.Read(stream);

        Assert.Equal(EmbeddedSignatureState.Present, result.State);
        Assert.Equal(encodedCms, result.SignedCms);
    }

    [Fact]
    public void RejectsNonzeroCertificatePadding()
    {
        byte[] bytes = CreatePortableExecutable([0x30, 0x03, 0x02, 0x01, 0x01]);
        bytes[^1] = 1;
        using MemoryStream stream = new(bytes);

        EmbeddedSignatureReadResult result = EmbeddedSignatureReader.Read(stream);

        Assert.Equal(EmbeddedSignatureState.Invalid, result.State);
    }

    [Fact]
    public void RejectsUnexpectedBytesAfterCertificateEntry()
    {
        byte[] bytes = CreatePortableExecutable([0x30, 0x03, 0x02, 0x01, 0x01]);
        Array.Resize(ref bytes, bytes.Length + 8);
        using MemoryStream stream = new(bytes);

        EmbeddedSignatureReadResult result = EmbeddedSignatureReader.Read(stream);

        Assert.Equal(EmbeddedSignatureState.Invalid, result.State);
    }

    [Theory]
    [InlineData(0x0100, 0x0002)]
    [InlineData(0x0200, 0x0001)]
    public void RejectsWrongCertificateHeader(ushort revision, ushort type)
    {
        byte[] bytes = CreatePortableExecutable([0x30, 0x00]);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(516, 2), revision);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(518, 2), type);
        using MemoryStream stream = new(bytes);

        EmbeddedSignatureReadResult result = EmbeddedSignatureReader.Read(stream);

        Assert.Equal(EmbeddedSignatureState.Invalid, result.State);
    }

    [Fact]
    public void RejectsTruncatedPortableExecutable()
    {
        using MemoryStream stream = new(new byte[255]);

        EmbeddedSignatureReadResult result = EmbeddedSignatureReader.Read(stream);

        Assert.Equal(EmbeddedSignatureState.Invalid, result.State);
    }

    [Fact]
    public void RejectsOversizedEmbeddedSignature()
    {
        byte[] encodedCms =
            new byte[EmbeddedSignatureReader.MaximumEmbeddedSignatureBytes + 1];
        using MemoryStream stream = new(CreatePortableExecutable(encodedCms));

        EmbeddedSignatureReadResult result = EmbeddedSignatureReader.Read(stream);

        Assert.Equal(EmbeddedSignatureState.Invalid, result.State);
    }

    private static byte[] CreatePortableExecutable(byte[]? encodedCms = null)
    {
        const int unsignedLength = 512;
        int certificateSize = encodedCms is null
            ? 0
            : Align8(8 + encodedCms.Length);
        byte[] bytes = new byte[unsignedLength + certificateSize];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        WriteUInt32(bytes, 0x3c, 0x80);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(0x80, 4));

        int coffOffset = 0x84;
        BinaryPrimitives.WriteUInt16LittleEndian(
            bytes.AsSpan(coffOffset + 16, 2),
            240);
        int optionalOffset = coffOffset + 20;
        BinaryPrimitives.WriteUInt16LittleEndian(
            bytes.AsSpan(optionalOffset, 2),
            0x020b);

        if (encodedCms is not null)
        {
            int securityDirectoryOffset = optionalOffset + 112 + (4 * 8);
            WriteUInt32(bytes, securityDirectoryOffset, unsignedLength);
            WriteUInt32(bytes, securityDirectoryOffset + 4, certificateSize);
            WriteUInt32(bytes, unsignedLength, 8 + encodedCms.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(
                bytes.AsSpan(unsignedLength + 4, 2),
                0x0200);
            BinaryPrimitives.WriteUInt16LittleEndian(
                bytes.AsSpan(unsignedLength + 6, 2),
                0x0002);
            encodedCms.CopyTo(bytes, unsignedLength + 8);
        }

        return bytes;
    }

    private static void WriteUInt32(byte[] bytes, int offset, int value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(offset, 4),
            checked((uint)value));
    }

    private static int Align8(int value)
    {
        return (value + 7) & ~7;
    }
}
