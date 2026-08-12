using System.Globalization;

namespace ArtifactSigning.TestProfile;

internal sealed record ExampleSemanticVersion : IComparable<ExampleSemanticVersion>
{
    private ExampleSemanticVersion(
        string original,
        ushort major,
        ushort minor,
        ushort patch,
        string[] preRelease)
    {
        Original = original;
        Major = major;
        Minor = minor;
        Patch = patch;
        PreRelease = preRelease;
    }

    internal string Original { get; }

    internal ushort Major { get; }

    internal ushort Minor { get; }

    internal ushort Patch { get; }

    internal IReadOnlyList<string> PreRelease { get; }

    internal Version FixedVersion => new(Major, Minor, Patch, 0);

    public int CompareTo(ExampleSemanticVersion? other)
    {
        if (other is null)
        {
            return 1;
        }

        int coreComparison = Major.CompareTo(other.Major);
        if (coreComparison is 0)
        {
            coreComparison = Minor.CompareTo(other.Minor);
        }

        if (coreComparison is 0)
        {
            coreComparison = Patch.CompareTo(other.Patch);
        }

        if (coreComparison is not 0)
        {
            return coreComparison;
        }

        if (PreRelease.Count is 0)
        {
            return other.PreRelease.Count is 0 ? 0 : 1;
        }

        if (other.PreRelease.Count is 0)
        {
            return -1;
        }

        for (int index = 0; index < Math.Min(PreRelease.Count, other.PreRelease.Count); index++)
        {
            string left = PreRelease[index];
            string right = other.PreRelease[index];
            bool leftNumeric = left.All(char.IsAsciiDigit);
            bool rightNumeric = right.All(char.IsAsciiDigit);

            int comparison;
            if (leftNumeric && rightNumeric)
            {
                comparison = left.Length.CompareTo(right.Length);
                if (comparison is 0)
                {
                    comparison = string.CompareOrdinal(left, right);
                }
            }
            else if (leftNumeric)
            {
                comparison = -1;
            }
            else if (rightNumeric)
            {
                comparison = 1;
            }
            else
            {
                comparison = string.CompareOrdinal(left, right);
            }

            if (comparison is not 0)
            {
                return comparison;
            }
        }

        return PreRelease.Count.CompareTo(other.PreRelease.Count);
    }

    internal static bool TryParse(string value, out ExampleSemanticVersion? version)
    {
        version = null;
        if (value.Length is 0 or > 64
            || value.Any(character =>
                !(char.IsAsciiLetterOrDigit(character)
                    || character is '.' or '-' or '+')))
        {
            return false;
        }

        string[] buildParts = value.Split('+');
        if (buildParts.Length > 2
            || buildParts.Length is 2 && !ValidateIdentifiers(
                buildParts[1],
                rejectLeadingZeroNumeric: false))
        {
            return false;
        }

        string[] releaseParts = buildParts[0].Split('-');
        if (releaseParts.Length > 2
            || releaseParts.Length is 2 && !ValidateIdentifiers(
                releaseParts[1],
                rejectLeadingZeroNumeric: true))
        {
            return false;
        }

        string[] core = releaseParts[0].Split('.');
        if (core.Length is not 3
            || !TryParseCore(core[0], out ushort major)
            || !TryParseCore(core[1], out ushort minor)
            || !TryParseCore(core[2], out ushort patch))
        {
            return false;
        }

        string[] preRelease = releaseParts.Length is 2
            ? releaseParts[1].Split('.')
            : [];
        version = new ExampleSemanticVersion(value, major, minor, patch, preRelease);
        return true;
    }

    private static bool TryParseCore(string value, out ushort result)
    {
        result = 0;
        return value.Length > 0
            && (value.Length is 1 || value[0] is not '0')
            && ushort.TryParse(
                value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out result);
    }

    private static bool ValidateIdentifiers(
        string value,
        bool rejectLeadingZeroNumeric)
    {
        string[] identifiers = value.Split('.');
        return identifiers.Length > 0
            && identifiers.All(identifier =>
                identifier.Length > 0
                && identifier.All(character =>
                    char.IsAsciiLetterOrDigit(character) || character is '-')
                && (!rejectLeadingZeroNumeric
                    || !identifier.All(char.IsAsciiDigit)
                    || identifier.Length is 1
                    || identifier[0] is not '0'));
    }
}
