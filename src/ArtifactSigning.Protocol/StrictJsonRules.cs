using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ArtifactSigning.Protocol;

internal enum StrictJsonError
{
    None,
    Malformed,
    NonCanonicalPropertyName,
    UnknownProperty,
    DuplicateProperty,
    MissingProperty,
}

internal static class StrictJsonRules
{
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    internal static StrictJsonError ValidateEncodingAndPropertyNames(
        ReadOnlySpan<byte> json,
        int maximumDepth)
    {
        try
        {
            _ = StrictUtf8.GetCharCount(json);

            Utf8JsonReader reader = new(
                json,
                new JsonReaderOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = maximumDepth,
                });

            while (reader.Read())
            {
                if (reader.TokenType is JsonTokenType.PropertyName && reader.ValueIsEscaped)
                {
                    return StrictJsonError.NonCanonicalPropertyName;
                }
            }

            return StrictJsonError.None;
        }
        catch (DecoderFallbackException)
        {
            return StrictJsonError.Malformed;
        }
        catch (JsonException)
        {
            return StrictJsonError.Malformed;
        }
    }

    internal static StrictJsonError ValidateObjectShape(
        JsonElement element,
        HashSet<string> expectedProperties)
    {
        HashSet<string> observedProperties = new(StringComparer.Ordinal);

        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!expectedProperties.Contains(property.Name))
            {
                return StrictJsonError.UnknownProperty;
            }

            if (!observedProperties.Add(property.Name))
            {
                return StrictJsonError.DuplicateProperty;
            }
        }

        return observedProperties.Count == expectedProperties.Count
            ? StrictJsonError.None
            : StrictJsonError.MissingProperty;
    }

    internal static bool TryGetString(
        JsonElement element,
        string propertyName,
        out string value)
    {
        if (element.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind is JsonValueKind.String)
        {
            string? parsed = property.GetString();
            if (parsed is not null)
            {
                value = parsed;
                return true;
            }
        }

        value = string.Empty;
        return false;
    }

    internal static bool TryGetInt32(
        JsonElement element,
        string propertyName,
        out int value)
    {
        if (element.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind is JsonValueKind.Number
            && property.TryGetInt32(out value))
        {
            return true;
        }

        value = 0;
        return false;
    }

    internal static bool TryGetInt64(
        JsonElement element,
        string propertyName,
        out long value)
    {
        if (element.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind is JsonValueKind.Number
            && property.TryGetInt64(out value))
        {
            return true;
        }

        value = 0;
        return false;
    }

    internal static bool TryParseCanonicalRequestId(string value, out Guid requestId)
    {
        return Guid.TryParseExact(value, "D", out requestId)
            && requestId != Guid.Empty
            && string.Equals(requestId.ToString("D"), value, StringComparison.Ordinal);
    }

    internal static bool TryParseWholeSecondUtc(string value, out DateTimeOffset timestamp)
    {
        return DateTimeOffset.TryParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out timestamp);
    }

    internal static bool IsCanonicalNonce(string value)
    {
        if (value.Length is not 43
            || value.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
        {
            return false;
        }

        try
        {
            string padded = value.Replace('-', '+').Replace('_', '/') + "=";
            byte[] decoded = Convert.FromBase64String(padded);
            if (decoded.Length is not 32)
            {
                return false;
            }

            string canonical = Convert.ToBase64String(decoded)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            return string.Equals(canonical, value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static bool IsSafeIdentifier(string value, int maximumCharacters)
    {
        return value.Length is > 0
            && value.Length <= maximumCharacters
            && char.IsAsciiLetterOrDigit(value[0])
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    }

    internal static bool IsPrintableAscii(string value, int maximumCharacters)
    {
        return value.Length is > 0
            && value.Length <= maximumCharacters
            && value[0] is not ' '
            && value[^1] is not ' '
            && value.All(character => character is >= '!' and <= '~');
    }

    internal static bool IsCanonicalSourceCommit(string value)
    {
        return (value.Length is 40 or 64) && IsLowerHex(value, value.Length);
    }

    internal static bool IsCanonicalFileToken(string value, int maximumCharacters)
    {
        return value.Length is > 0
            && value.Length <= maximumCharacters
            && value is not "." and not ".."
            && value[^1] is not '.' and not ' '
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    }

    internal static bool IsLowerHex(string value, int requiredCharacters)
    {
        return value.Length == requiredCharacters
            && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }
}
