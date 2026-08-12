namespace ArtifactSigning.Windows;

internal static class WindowsContractRules
{
    internal static bool IsLowerSha256(string value)
    {
        return IsHex(value, 64, uppercase: false);
    }

    internal static bool IsUpperCertificateThumbprint(string value)
    {
        return IsHex(value, 40, uppercase: true);
    }

    internal static bool IsAbsoluteLeafPath(string value, string requiredLeafName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        bool hasWindowsDrivePrefix = value.Length >= 3
            && char.IsAsciiLetter(value[0])
            && value[1] is ':'
            && value[2] is '\\';
        if (!hasWindowsDrivePrefix)
        {
            return !OperatingSystem.IsWindows()
                && Path.IsPathFullyQualified(value)
                && string.Equals(
                    Path.GetFileName(value),
                    requiredLeafName,
                    StringComparison.OrdinalIgnoreCase);
        }

        if (value.Length > 260
            || value.Contains('/', StringComparison.Ordinal))
        {
            return false;
        }

        string[] segments = value[3..].Split('\\');
        if (segments.Length is 0
            || segments.Any(segment =>
                !IsSafeWindowsPathSegment(segment)))
        {
            return false;
        }

        return string.Equals(
            segments[^1],
            requiredLeafName,
            StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSafeWindowsPathSegment(string segment)
    {
        if (segment.Length is 0 or > 255
            || segment is "." or ".."
            || segment[^1] is ' ' or '.'
            || segment.Any(character =>
                character < 32
                || character is '\\' or '/' or ':' or '*' or '?'
                    or '"' or '<' or '>' or '|'))
        {
            return false;
        }

        string baseName = segment.Split('.')[0];
        return !baseName.Equals("CON", StringComparison.OrdinalIgnoreCase)
            && !baseName.Equals("PRN", StringComparison.OrdinalIgnoreCase)
            && !baseName.Equals("AUX", StringComparison.OrdinalIgnoreCase)
            && !baseName.Equals("NUL", StringComparison.OrdinalIgnoreCase)
            && !IsNumberedDeviceName(baseName, "COM")
            && !IsNumberedDeviceName(baseName, "LPT");
    }

    private static bool IsNumberedDeviceName(
        string value,
        string prefix)
    {
        return value.Length is 4
            && value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            && value[3] is >= '1' and <= '9';
    }

    private static bool IsHex(string value, int length, bool uppercase)
    {
        if (value.Length != length)
        {
            return false;
        }

        foreach (char character in value)
        {
            if (char.IsAsciiDigit(character))
            {
                continue;
            }

            bool isHexLetter = uppercase
                ? character is >= 'A' and <= 'F'
                : character is >= 'a' and <= 'f';
            if (!isHexLetter)
            {
                return false;
            }
        }

        return true;
    }
}
