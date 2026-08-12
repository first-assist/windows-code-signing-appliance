using System.Buffers.Binary;
using System.Text;

namespace ArtifactSigning.TestProfile;

internal enum PortableExecutableInspectionError
{
    None,
    InvalidFormat,
    SignaturePresent,
    SignatureMissing,
}

internal enum PortableExecutableSignatureRequirement
{
    Unsigned,
    EmbeddedSignature,
}

internal sealed record PortableExecutableInformation(
    Version FixedFileVersion,
    Version FixedProductVersion,
    string CompanyName,
    string FileDescription,
    string FileVersion,
    string InternalName,
    string OriginalFileName,
    string ProductName,
    string ProductVersion);

internal sealed record PortableExecutableInspectionResult(
    PortableExecutableInformation? Information,
    PortableExecutableInspectionError Error)
{
    internal bool IsSuccess =>
        Error is PortableExecutableInspectionError.None && Information is not null;
}

internal static class PortableExecutableInspector
{
    private const ushort Amd64Machine = 0x8664;
    private const ushort Pe32PlusMagic = 0x020b;
    private const ushort ExecutableImage = 0x0002;
    private const ushort DynamicLibrary = 0x2000;
    private const uint VersionResourceIdentifier = 16;
    private const uint ResourceDirectoryFlag = 0x80000000;
    private const uint FixedFileInformationSignature = 0xfeef04bd;
    private const uint ApplicationFileType = 0x00000001;
    private const int MaximumSections = 96;
    private const int MaximumResourceDirectoryEntries = 128;
    private const int MaximumResourceDirectoryBytes = 4 * 1024 * 1024;
    private const int MaximumVersionResourceBytes = 64 * 1024;

    private static readonly string[] RequiredStringFields =
    [
        "CompanyName",
        "FileDescription",
        "FileVersion",
        "InternalName",
        "OriginalFilename",
        "ProductName",
        "ProductVersion",
    ];

    internal static PortableExecutableInspectionResult InspectUnsigned(Stream stream)
    {
        return Inspect(stream, PortableExecutableSignatureRequirement.Unsigned);
    }

    internal static PortableExecutableInspectionResult InspectSigned(Stream stream)
    {
        return Inspect(stream, PortableExecutableSignatureRequirement.EmbeddedSignature);
    }

    private static PortableExecutableInspectionResult Inspect(
        Stream stream,
        PortableExecutableSignatureRequirement signatureRequirement)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (!stream.CanRead || !stream.CanSeek)
        {
            return Failure(PortableExecutableInspectionError.InvalidFormat);
        }

        try
        {
            long fileLength = stream.Length;
            if (fileLength is < 512 or > ExampleEndpointBundleV1.MaximumPortableExecutableBytes
                || ReadUInt16(stream, 0) is not 0x5a4d)
            {
                return Failure(PortableExecutableInspectionError.InvalidFormat);
            }

            uint peOffset = ReadUInt32(stream, 0x3c);
            if (peOffset < 64
                || !ReadBytes(stream, peOffset, 4).AsSpan().SequenceEqual("PE\0\0"u8))
            {
                return Failure(PortableExecutableInspectionError.InvalidFormat);
            }

            long coffOffset = checked(peOffset + 4);
            ushort machine = ReadUInt16(stream, coffOffset);
            ushort sectionCount = ReadUInt16(stream, coffOffset + 2);
            ushort optionalHeaderBytes = ReadUInt16(stream, coffOffset + 16);
            ushort characteristics = ReadUInt16(stream, coffOffset + 18);
            if (machine != Amd64Machine
                || sectionCount is 0 or > MaximumSections
                || optionalHeaderBytes < 240
                || !HasFlag(characteristics, ExecutableImage)
                || HasFlag(characteristics, DynamicLibrary))
            {
                return Failure(PortableExecutableInspectionError.InvalidFormat);
            }

            long optionalOffset = checked(coffOffset + 20);
            if (ReadUInt16(stream, optionalOffset) != Pe32PlusMagic
                || ReadUInt32(stream, optionalOffset + 108) < 16)
            {
                return Failure(PortableExecutableInspectionError.InvalidFormat);
            }

            long dataDirectoriesOffset = checked(optionalOffset + 112);
            uint resourceRva = ReadUInt32(stream, dataDirectoriesOffset + (2 * 8));
            uint resourceSize = ReadUInt32(stream, dataDirectoriesOffset + (2 * 8) + 4);
            uint certificateOffset = ReadUInt32(stream, dataDirectoriesOffset + (4 * 8));
            uint certificateSize = ReadUInt32(stream, dataDirectoriesOffset + (4 * 8) + 4);
            if (signatureRequirement is PortableExecutableSignatureRequirement.Unsigned
                && (certificateOffset is not 0 || certificateSize is not 0))
            {
                return Failure(PortableExecutableInspectionError.SignaturePresent);
            }

            if (signatureRequirement is PortableExecutableSignatureRequirement.EmbeddedSignature
                && (certificateOffset is 0 || certificateSize is 0))
            {
                return Failure(PortableExecutableInspectionError.SignatureMissing);
            }

            if (resourceRva is 0
                || resourceSize is 0 or > MaximumResourceDirectoryBytes)
            {
                return Failure(PortableExecutableInspectionError.InvalidFormat);
            }

            long sectionTableOffset = checked(optionalOffset + optionalHeaderBytes);
            PeSection[] sections = ReadSections(
                stream,
                sectionTableOffset,
                sectionCount,
                fileLength);
            if (signatureRequirement is PortableExecutableSignatureRequirement.EmbeddedSignature)
            {
                ValidateCertificateTable(
                    stream,
                    certificateOffset,
                    certificateSize,
                    sections,
                    fileLength);
            }

            long resourceBase = MapRvaToFileOffset(resourceRva, sections, fileLength);
            VersionResourceLocation versionLocation = FindVersionResource(
                stream,
                resourceBase,
                resourceSize,
                sections,
                fileLength);
            if (versionLocation.Size is 0 or > MaximumVersionResourceBytes)
            {
                return Failure(PortableExecutableInspectionError.InvalidFormat);
            }

            byte[] versionBytes = ReadBytes(
                stream,
                versionLocation.FileOffset,
                checked((int)versionLocation.Size));
            PortableExecutableInformation? information = ParseVersionInformation(versionBytes);
            return information is null
                ? Failure(PortableExecutableInspectionError.InvalidFormat)
                : new PortableExecutableInspectionResult(
                    information,
                    PortableExecutableInspectionError.None);
        }
        catch (EndOfStreamException)
        {
            return Failure(PortableExecutableInspectionError.InvalidFormat);
        }
        catch (InvalidDataException)
        {
            return Failure(PortableExecutableInspectionError.InvalidFormat);
        }
        catch (IOException)
        {
            return Failure(PortableExecutableInspectionError.InvalidFormat);
        }
        catch (OverflowException)
        {
            return Failure(PortableExecutableInspectionError.InvalidFormat);
        }
        catch (ArgumentOutOfRangeException)
        {
            return Failure(PortableExecutableInspectionError.InvalidFormat);
        }
    }

    private static void ValidateCertificateTable(
        Stream stream,
        uint certificateOffset,
        uint certificateSize,
        IEnumerable<PeSection> sections,
        long fileLength)
    {
        long certificateEnd = checked((long)certificateOffset + certificateSize);
        long sectionDataEnd = sections.Max(
            section => checked((long)section.RawOffset + section.RawSize));
        if (certificateOffset % 8 is not 0
            || certificateSize < 8
            || certificateOffset < sectionDataEnd
            || certificateEnd != fileLength)
        {
            throw new InvalidDataException();
        }

        uint entryLength = ReadUInt32(stream, certificateOffset);
        ushort revision = ReadUInt16(stream, certificateOffset + 4);
        ushort certificateType = ReadUInt16(stream, certificateOffset + 6);
        if (entryLength < 8
            || revision is not 0x0200
            || certificateType is not 0x0002
            || Align8(checked((long)certificateOffset + entryLength)) != certificateEnd)
        {
            throw new InvalidDataException();
        }
    }

    private static PeSection[] ReadSections(
        Stream stream,
        long sectionTableOffset,
        ushort sectionCount,
        long fileLength)
    {
        PeSection[] sections = new PeSection[sectionCount];
        for (int index = 0; index < sectionCount; index++)
        {
            long offset = checked(sectionTableOffset + (index * 40L));
            uint virtualSize = ReadUInt32(stream, offset + 8);
            uint virtualAddress = ReadUInt32(stream, offset + 12);
            uint rawSize = ReadUInt32(stream, offset + 16);
            uint rawOffset = ReadUInt32(stream, offset + 20);
            if (rawSize > 0 && checked((long)rawOffset + rawSize) > fileLength)
            {
                throw new EndOfStreamException();
            }

            sections[index] = new PeSection(
                virtualAddress,
                virtualSize,
                rawOffset,
                rawSize);
        }

        return sections;
    }

    private static VersionResourceLocation FindVersionResource(
        Stream stream,
        long resourceBase,
        uint resourceSize,
        IReadOnlyList<PeSection> sections,
        long fileLength)
    {
        List<ResourceDirectoryEntry> rootEntries = ReadResourceDirectory(
            stream,
            resourceBase,
            resourceBase,
            resourceSize);
        ResourceDirectoryEntry[] versionEntries = rootEntries
            .Where(entry =>
                !entry.NameIsString && entry.Identifier == VersionResourceIdentifier)
            .ToArray();
        if (versionEntries.Length is not 1 || !versionEntries[0].IsDirectory)
        {
            throw new InvalidDataException();
        }

        long typeDirectory = ResolveResourceRelativeOffset(
            resourceBase,
            resourceSize,
            versionEntries[0].Offset);
        List<ResourceDirectoryEntry> nameEntries = ReadResourceDirectory(
            stream,
            resourceBase,
            typeDirectory,
            resourceSize);
        if (nameEntries.Count is not 1 || !nameEntries[0].IsDirectory)
        {
            throw new InvalidDataException();
        }

        long languageDirectory = ResolveResourceRelativeOffset(
            resourceBase,
            resourceSize,
            nameEntries[0].Offset);
        List<ResourceDirectoryEntry> languageEntries = ReadResourceDirectory(
            stream,
            resourceBase,
            languageDirectory,
            resourceSize);
        if (languageEntries.Count is not 1 || languageEntries[0].IsDirectory)
        {
            throw new InvalidDataException();
        }

        long dataEntryOffset = ResolveResourceRelativeOffset(
            resourceBase,
            resourceSize,
            languageEntries[0].Offset);
        uint dataRva = ReadUInt32(stream, dataEntryOffset);
        uint dataSize = ReadUInt32(stream, dataEntryOffset + 4);
        long fileOffset = MapRvaToFileOffset(dataRva, sections, fileLength);
        if (checked(fileOffset + dataSize) > fileLength)
        {
            throw new EndOfStreamException();
        }

        return new VersionResourceLocation(fileOffset, dataSize);
    }

    private static List<ResourceDirectoryEntry> ReadResourceDirectory(
        Stream stream,
        long resourceBase,
        long directoryOffset,
        uint resourceSize)
    {
        EnsureResourceRange(resourceBase, resourceSize, directoryOffset, 16);
        ushort namedCount = ReadUInt16(stream, directoryOffset + 12);
        ushort identifierCount = ReadUInt16(stream, directoryOffset + 14);
        int entryCount = checked(namedCount + identifierCount);
        if (entryCount is 0 or > MaximumResourceDirectoryEntries)
        {
            throw new InvalidDataException();
        }

        EnsureResourceRange(
            resourceBase,
            resourceSize,
            directoryOffset + 16,
            checked(entryCount * 8L));
        List<ResourceDirectoryEntry> entries = new(entryCount);
        for (int index = 0; index < entryCount; index++)
        {
            long entryOffset = checked(directoryOffset + 16 + (index * 8L));
            uint name = ReadUInt32(stream, entryOffset);
            uint target = ReadUInt32(stream, entryOffset + 4);
            entries.Add(
                new ResourceDirectoryEntry(
                    NameIsString: (name & ResourceDirectoryFlag) != 0,
                    Identifier: name & 0xffff,
                    IsDirectory: (target & ResourceDirectoryFlag) != 0,
                    Offset: target & ~ResourceDirectoryFlag));
        }

        return entries;
    }

    private static long ResolveResourceRelativeOffset(
        long resourceBase,
        uint resourceSize,
        uint relativeOffset)
    {
        long resolved = checked(resourceBase + relativeOffset);
        EnsureResourceRange(resourceBase, resourceSize, resolved, 1);
        return resolved;
    }

    private static void EnsureResourceRange(
        long resourceBase,
        uint resourceSize,
        long offset,
        long length)
    {
        long resourceEnd = checked(resourceBase + resourceSize);
        if (offset < resourceBase
            || length < 0
            || checked(offset + length) > resourceEnd)
        {
            throw new InvalidDataException();
        }
    }

    private static long MapRvaToFileOffset(
        uint rva,
        IEnumerable<PeSection> sections,
        long fileLength)
    {
        foreach (PeSection section in sections)
        {
            uint mappedSize = Math.Max(section.VirtualSize, section.RawSize);
            if (mappedSize is 0
                || rva < section.VirtualAddress
                || (ulong)rva >= (ulong)section.VirtualAddress + mappedSize)
            {
                continue;
            }

            uint relative = rva - section.VirtualAddress;
            if (relative >= section.RawSize)
            {
                throw new InvalidDataException();
            }

            long fileOffset = checked((long)section.RawOffset + relative);
            if (fileOffset >= fileLength)
            {
                throw new EndOfStreamException();
            }

            return fileOffset;
        }

        throw new InvalidDataException();
    }

    private static PortableExecutableInformation? ParseVersionInformation(
        ReadOnlySpan<byte> data)
    {
        Dictionary<string, string> strings = new(StringComparer.Ordinal);
        FixedVersionInformation? fixedInformation = null;
        if (!ParseVersionBlock(
                data,
                offset: 0,
                enclosingEnd: data.Length,
                depth: 0,
                strings,
                ref fixedInformation,
                out int rootLength)
            || fixedInformation is null
            || data[rootLength..].ContainsAnyExcept((byte)0)
            || RequiredStringFields.Any(field => !strings.ContainsKey(field)))
        {
            return null;
        }

        return new PortableExecutableInformation(
            fixedInformation.FileVersion,
            fixedInformation.ProductVersion,
            strings["CompanyName"],
            strings["FileDescription"],
            strings["FileVersion"],
            strings["InternalName"],
            strings["OriginalFilename"],
            strings["ProductName"],
            strings["ProductVersion"]);
    }

    private static bool ParseVersionBlock(
        ReadOnlySpan<byte> data,
        int offset,
        int enclosingEnd,
        int depth,
        Dictionary<string, string> strings,
        ref FixedVersionInformation? fixedInformation,
        out int blockLength)
    {
        blockLength = 0;
        if (depth > 8 || offset < 0 || offset + 6 > enclosingEnd)
        {
            return false;
        }

        int length = ReadUInt16(data, offset);
        int valueLength = ReadUInt16(data, offset + 2);
        int type = ReadUInt16(data, offset + 4);
        int blockEnd = checked(offset + length);
        if (length < 6 || blockEnd > enclosingEnd)
        {
            return false;
        }

        if (!TryReadUtf16NullTerminated(
                data,
                offset + 6,
                blockEnd,
                out string key,
                out int keyEnd))
        {
            return false;
        }

        int valueOffset = Align4(keyEnd);
        int valueBytes = checked(valueLength * (type is 1 ? 2 : 1));
        int valueEnd = checked(valueOffset + valueBytes);
        if (valueOffset > blockEnd || valueEnd > blockEnd)
        {
            return false;
        }

        if (depth is 0)
        {
            if (!string.Equals(key, "VS_VERSION_INFO", StringComparison.Ordinal)
                || type is not 0
                || valueLength is not 52
                || !TryParseFixedVersionInformation(
                    data[valueOffset..valueEnd],
                    out fixedInformation))
            {
                return false;
            }
        }
        else if (RequiredStringFields.Contains(key, StringComparer.Ordinal))
        {
            if (type is not 1
                || valueLength is 0
                || !TryDecodeVersionString(
                    data[valueOffset..valueEnd],
                    out string value)
                || !strings.TryAdd(key, value))
            {
                return false;
            }
        }

        int childOffset = Align4(valueEnd);
        while (childOffset + 2 <= blockEnd)
        {
            if (data[childOffset..blockEnd].ContainsAnyExcept((byte)0) is false)
            {
                break;
            }

            int childLength = ReadUInt16(data, childOffset);
            if (childLength is 0
                || !ParseVersionBlock(
                    data,
                    childOffset,
                    blockEnd,
                    depth + 1,
                    strings,
                    ref fixedInformation,
                    out int parsedChildLength))
            {
                return false;
            }

            childOffset = Align4(checked(childOffset + parsedChildLength));
        }

        blockLength = length;
        return true;
    }

    private static bool TryParseFixedVersionInformation(
        ReadOnlySpan<byte> value,
        out FixedVersionInformation? information)
    {
        information = null;
        if (value.Length is not 52
            || ReadUInt32(value, 0) != FixedFileInformationSignature
            || ReadUInt32(value, 36) != ApplicationFileType)
        {
            return false;
        }

        information = new FixedVersionInformation(
            ToVersion(ReadUInt32(value, 8), ReadUInt32(value, 12)),
            ToVersion(ReadUInt32(value, 16), ReadUInt32(value, 20)));
        return true;
    }

    private static Version ToVersion(uint mostSignificant, uint leastSignificant)
    {
        return new Version(
            checked((int)(mostSignificant >> 16)),
            checked((int)(mostSignificant & 0xffff)),
            checked((int)(leastSignificant >> 16)),
            checked((int)(leastSignificant & 0xffff)));
    }

    private static bool TryDecodeVersionString(
        ReadOnlySpan<byte> value,
        out string result)
    {
        result = string.Empty;
        if (value.Length < 2
            || value.Length % 2 is not 0
            || BinaryPrimitives.ReadUInt16LittleEndian(value[^2..]) is not 0)
        {
            return false;
        }

        string parsed = Encoding.Unicode.GetString(value[..^2]);
        if (parsed.Length is 0 || parsed.Contains('\0', StringComparison.Ordinal))
        {
            return false;
        }

        result = parsed;
        return true;
    }

    private static bool TryReadUtf16NullTerminated(
        ReadOnlySpan<byte> data,
        int offset,
        int end,
        out string value,
        out int valueEnd)
    {
        value = string.Empty;
        valueEnd = offset;
        for (int current = offset; current + 2 <= end; current += 2)
        {
            if (ReadUInt16(data, current) is not 0)
            {
                continue;
            }

            value = Encoding.Unicode.GetString(data[offset..current]);
            valueEnd = current + 2;
            return value.Length > 0;
        }

        return false;
    }

    private static bool HasFlag(ushort value, ushort flag)
    {
        return (value & flag) == flag;
    }

    private static int Align4(int value)
    {
        return checked((value + 3) & ~3);
    }

    private static long Align8(long value)
    {
        return checked((value + 7) & ~7L);
    }

    private static ushort ReadUInt16(Stream stream, long offset)
    {
        Span<byte> bytes = stackalloc byte[2];
        ReadExactly(stream, offset, bytes);
        return BinaryPrimitives.ReadUInt16LittleEndian(bytes);
    }

    private static uint ReadUInt32(Stream stream, long offset)
    {
        Span<byte> bytes = stackalloc byte[4];
        ReadExactly(stream, offset, bytes);
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset)
    {
        if (offset < 0 || offset + 2 > data.Length)
        {
            throw new EndOfStreamException();
        }

        return BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset)
    {
        if (offset < 0 || offset + 4 > data.Length)
        {
            throw new EndOfStreamException();
        }

        return BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);
    }

    private static byte[] ReadBytes(Stream stream, long offset, int count)
    {
        byte[] result = new byte[count];
        ReadExactly(stream, offset, result);
        return result;
    }

    private static void ReadExactly(Stream stream, long offset, Span<byte> destination)
    {
        if (offset < 0 || checked(offset + destination.Length) > stream.Length)
        {
            throw new EndOfStreamException();
        }

        stream.Position = offset;
        stream.ReadExactly(destination);
    }

    private static PortableExecutableInspectionResult Failure(
        PortableExecutableInspectionError error)
    {
        return new PortableExecutableInspectionResult(null, error);
    }

    private sealed record PeSection(
        uint VirtualAddress,
        uint VirtualSize,
        uint RawOffset,
        uint RawSize);

    private sealed record ResourceDirectoryEntry(
        bool NameIsString,
        uint Identifier,
        bool IsDirectory,
        uint Offset);

    private sealed record VersionResourceLocation(long FileOffset, uint Size);

    private sealed record FixedVersionInformation(
        Version FileVersion,
        Version ProductVersion);
}
