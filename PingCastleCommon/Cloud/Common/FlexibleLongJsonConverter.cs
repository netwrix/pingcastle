namespace PingCastle.Cloud.Common;

using System;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// Custom JSON converter that handles long values that may come as either numeric or string formats.
///
/// This converter is needed to handle different Azure AD tenant configurations where JWT timestamp claims
/// (iat, exp, nbf) might be serialized as either numbers or strings.
///
/// Issue #417371: Customer receives error "The JSON value could not be converted to System.Int64. Path: $.iat"
/// </summary>
public class FlexibleLongJsonConverter : JsonConverter<long>
{
    public override long Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Number:
                // Handle numeric format: "iat": 1645812345
                if (reader.TryGetInt64(out long value))
                {
                    return value;
                }

                // If it's too large for int64, try double first
                if (reader.TryGetDouble(out double doubleValue))
                {
                    // Verify it's actually an integer with no fractional part
                    if (doubleValue % 1 != 0)
                    {
                        throw new JsonException($"Double value '{doubleValue}' has fractional part - expected integer timestamp");
                    }

                    // Verify it's in valid range for long
                    if (doubleValue < long.MinValue || doubleValue > long.MaxValue)
                    {
                        throw new JsonException($"Double value '{doubleValue}' is out of range for Int64");
                    }

                    return (long)doubleValue;
                }

                throw new JsonException($"Cannot convert number to Int64");

            case JsonTokenType.String:
                // Handle string format: "iat": "1645812345"
                string stringValue = reader.GetString();

                if (string.IsNullOrEmpty(stringValue))
                {
                    throw new JsonException("Empty string cannot be converted to Int64");
                }

                // Trim to ensure no leading/trailing whitespace interferes with parsing
                stringValue = stringValue.Trim();

                // Try to parse the string as a long
                if (long.TryParse(stringValue, out long parsedValue))
                {
                    return parsedValue;
                }

                throw new JsonException($"String value '{stringValue}' cannot be converted to Int64");

            case JsonTokenType.Null:
                throw new JsonException("Null value cannot be converted to Int64");

            default:
                throw new JsonException($"Unexpected token type {reader.TokenType} when parsing long value");
        }
    }

    public override void Write(Utf8JsonWriter writer, long value, JsonSerializerOptions options)
    {
        // Always write as numeric format for consistency
        writer.WriteNumberValue(value);
    }
}