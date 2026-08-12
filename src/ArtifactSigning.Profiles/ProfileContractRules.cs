namespace ArtifactSigning.Profiles;

internal static class ProfileContractRules
{
    internal static bool IsSafeIdentifier(string value, int maximumCharacters)
    {
        return value.Length is > 0
            && value.Length <= maximumCharacters
            && char.IsAsciiLetterOrDigit(value[0])
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    }

    internal static bool IsLeafFileName(string value, int maximumCharacters)
    {
        return value.Length is > 0
            && value.Length <= maximumCharacters
            && value is not "." and not ".."
            && value[^1] is not '.' and not ' '
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    }

    internal static bool IsSourceRepository(string value, int maximumSegmentCharacters)
    {
        if (value.Length is 0 or > 128
            || value[0] is '/'
            || value[^1] is '/')
        {
            return false;
        }

        string[] segments = value.Split('/');
        return segments.Length is > 0 and <= 8
            && segments.All(segment =>
                IsLeafFileName(segment, maximumSegmentCharacters));
    }

    internal static bool IsLowerSha256(string value)
    {
        return value.Length is 64
            && value.All(character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    internal static bool IsUpperCertificateThumbprint(string value)
    {
        return value.Length is 40
            && value.All(character =>
                character is >= '0' and <= '9' or >= 'A' and <= 'F');
    }

    internal static bool IsWholeSecond(DateTimeOffset value)
    {
        return value.Ticks % TimeSpan.TicksPerSecond is 0;
    }

    internal static bool IsCanonicalSemanticVersion(string value)
    {
        if (value.Length is 0 or > 128)
        {
            return false;
        }

        int buildSeparator = value.AsSpan().IndexOf('+');
        if (buildSeparator >= 0
            && value.AsSpan((buildSeparator + 1)..).IndexOf('+') >= 0)
        {
            return false;
        }

        string core = buildSeparator < 0 ? value : value[..buildSeparator];
        string? build = buildSeparator < 0 ? null : value[(buildSeparator + 1)..];
        return IsSemanticVersionCore(core)
            && (build is null || IsSemanticIdentifierList(build, numericNoLeadingZero: false));
    }

    private static bool IsSemanticVersionCore(string value)
    {
        int preReleaseSeparator = value.AsSpan().IndexOf('-');
        string core = preReleaseSeparator < 0 ? value : value[..preReleaseSeparator];
        string? preRelease = preReleaseSeparator < 0 ? null : value[(preReleaseSeparator + 1)..];
        return IsSemanticCore(core)
            && (preRelease is null
                || IsSemanticIdentifierList(preRelease, numericNoLeadingZero: true));
    }

    private static bool IsSemanticCore(string value)
    {
        string[] numericParts = value.Split('.');
        return numericParts.Length is 3
            && numericParts.All(part => IsSemanticNumericIdentifier(part, noLeadingZero: true));
    }

    private static bool IsSemanticIdentifierList(string value, bool numericNoLeadingZero)
    {
        string[] identifiers = value.Split('.');
        return identifiers.Length is > 0 and <= 16
            && identifiers.All(identifier =>
                identifier.Length is > 0 and <= 32
                && identifier.All(character => char.IsAsciiLetterOrDigit(character) || character is '-')
                && (!numericNoLeadingZero
                    || !identifier.All(char.IsAsciiDigit)
                    || IsSemanticNumericIdentifier(identifier, noLeadingZero: true)));
    }

    private static bool IsSemanticNumericIdentifier(string value, bool noLeadingZero)
    {
        return value.Length is > 0 and <= 10
            && value.All(char.IsAsciiDigit)
            && (!noLeadingZero || value.Length is 1 || value[0] is not '0');
    }
}
