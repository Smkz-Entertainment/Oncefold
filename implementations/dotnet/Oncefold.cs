using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Oncefold.DotNet;

public sealed class ProtocolException : Exception
{
    public ProtocolException(string message) : base(message) { }
    public ProtocolException(string message, Exception innerException) : base(message, innerException) { }
}

public static class CanonicalJson
{
    public const int MaxStringLength = 4096;
    public const int MaxCollectionLength = 256;
    public const int MaxCanonicalDepth = 16;
    public const int MaxJsonBytes = 1_048_576;
    public const int MaxJsonDepth = 32;

    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);
    private static readonly char[] Hex = "0123456789abcdef".ToCharArray();

    public static string Canonicalize(object? value)
    {
        var normalized = Normalize(value, 0);
        var builder = new StringBuilder();
        Write(builder, normalized);
        return builder.ToString();
    }

    public static string Sha256(string value)
    {
        var digest = SHA256.HashData(Utf8.GetBytes(value));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    public static string Text(object? value, string field, bool required = true, int maxLength = MaxStringLength)
    {
        if (value is not string text)
            throw new ProtocolException($"{field} must be a string");
        if (required && text.Length == 0)
            throw new ProtocolException($"{field} is required");
        string normalized;
        try
        {
            normalized = text.Normalize(NormalizationForm.FormC);
        }
        catch (ArgumentException exception)
        {
            throw new ProtocolException($"{field} contains an invalid Unicode scalar", exception);
        }
        ValidateScalars(normalized, field, maxLength);
        return normalized;
    }

    public static int CompareUtf8(string left, string right)
    {
        var leftBytes = Utf8.GetBytes(left);
        var rightBytes = Utf8.GetBytes(right);
        var length = Math.Min(leftBytes.Length, rightBytes.Length);
        for (var index = 0; index < length; index++)
        {
            if (leftBytes[index] != rightBytes[index])
                return leftBytes[index].CompareTo(rightBytes[index]);
        }
        return leftBytes.Length.CompareTo(rightBytes.Length);
    }

    public static object? Clone(object? value)
    {
        if (value is Dictionary<string, object?> map)
        {
            var copy = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var pair in map)
                copy[pair.Key] = Clone(pair.Value);
            return copy;
        }
        if (value is List<object?> list)
            return list.Select(Clone).ToList();
        return value;
    }

    private static object? Normalize(object? value, int depth)
    {
        if (depth > MaxCanonicalDepth)
            throw new ProtocolException("canonical value is too deeply nested");
        if (value is null || value is bool)
            return value;
        if (value is string text)
            return Text(text, "canonical string", required: false);
        if (value is Dictionary<string, object?> map)
        {
            if (map.Count > MaxCollectionLength)
                throw new ProtocolException("canonical object exceeds bound");
            var normalized = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var pair in map)
            {
                var key = Text(pair.Key, "canonical object key", required: false);
                if (!normalized.TryAdd(key, Normalize(pair.Value, depth + 1)))
                    throw new ProtocolException("canonical key collision");
            }
            return normalized;
        }
        if (value is List<object?> list)
        {
            if (list.Count > MaxCollectionLength)
                throw new ProtocolException("canonical array exceeds bound");
            return list.Select(item => Normalize(item, depth + 1)).ToList();
        }
        throw new ProtocolException($"unsupported canonical value {value.GetType().Name}");
    }

    private static void ValidateScalars(string value, string field, int maxLength)
    {
        var scalarCount = 0;
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            int codePoint;
            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                    throw new ProtocolException($"{field} contains an invalid Unicode scalar");
                codePoint = char.ConvertToUtf32(character, value[++index]);
            }
            else if (char.IsLowSurrogate(character))
            {
                throw new ProtocolException($"{field} contains an invalid Unicode scalar");
            }
            else
            {
                codePoint = character;
            }
            scalarCount++;
            if (codePoint < 0x20)
                throw new ProtocolException($"{field} contains a control character");
            if (codePoint is 0x2028 or 0x2029)
                throw new ProtocolException($"{field} contains a prohibited line-separator code point");
        }
        if (scalarCount > maxLength)
            throw new ProtocolException($"{field} exceeds canonical bounds");
    }

    private static void Write(StringBuilder builder, object? value)
    {
        switch (value)
        {
            case null:
                builder.Append("null");
                return;
            case bool boolean:
                builder.Append(boolean ? "true" : "false");
                return;
            case string text:
                WriteString(builder, text);
                return;
            case List<object?> list:
                builder.Append('[');
                for (var index = 0; index < list.Count; index++)
                {
                    if (index > 0) builder.Append(',');
                    Write(builder, list[index]);
                }
                builder.Append(']');
                return;
            case Dictionary<string, object?> map:
                builder.Append('{');
                var entries = map.Keys.OrderBy(key => key, Utf8Comparer.Instance).ToArray();
                for (var index = 0; index < entries.Length; index++)
                {
                    if (index > 0) builder.Append(',');
                    WriteString(builder, entries[index]);
                    builder.Append(':');
                    Write(builder, map[entries[index]]);
                }
                builder.Append('}');
                return;
            default:
                throw new ProtocolException($"unsupported canonical value {value.GetType().Name}");
        }
    }

    private static void WriteString(StringBuilder builder, string value)
    {
        builder.Append('"');
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            switch (character)
            {
                case '"': builder.Append("\\\""); break;
                case '\\': builder.Append("\\\\"); break;
                case '\b': builder.Append("\\b"); break;
                case '\f': builder.Append("\\f"); break;
                case '\n': builder.Append("\\n"); break;
                case '\r': builder.Append("\\r"); break;
                case '\t': builder.Append("\\t"); break;
                default:
                    if (character < 0x20)
                    {
                        builder.Append("\\u");
                        builder.Append(Hex[(character >> 12) & 0xf]);
                        builder.Append(Hex[(character >> 8) & 0xf]);
                        builder.Append(Hex[(character >> 4) & 0xf]);
                        builder.Append(Hex[character & 0xf]);
                    }
                    else
                    {
                        builder.Append(character);
                    }
                    break;
            }
        }
        builder.Append('"');
    }

    private sealed class Utf8Comparer : IComparer<string>
    {
        public static Utf8Comparer Instance { get; } = new();
        public int Compare(string? left, string? right) => CanonicalJson.CompareUtf8(left ?? string.Empty, right ?? string.Empty);
    }
}

public sealed class WireParser
{
    private readonly string _source;
    private int _position;

    private WireParser(string source) => _source = source;

    public static Dictionary<string, object?> ParseObject(byte[] bytes)
    {
        if (bytes.Length > CanonicalJson.MaxJsonBytes)
            throw new ProtocolException("JSON input exceeds the 1 MiB bound");
        string source;
        try
        {
            source = new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw new ProtocolException("JSON input is not valid UTF-8", exception);
        }
        var parser = new WireParser(source);
        var value = parser.ParseValue(1);
        parser.SkipWhitespace();
        if (parser._position != source.Length)
            throw new ProtocolException("trailing JSON input");
        return value as Dictionary<string, object?>
            ?? throw new ProtocolException("JSON document must be an object");
    }

    private object? ParseValue(int depth)
    {
        SkipWhitespace();
        if (_position >= _source.Length)
            throw new ProtocolException("unexpected end of JSON input");
        return _source[_position] switch
        {
            '{' => ParseObjectValue(depth),
            '[' => ParseArrayValue(depth),
            '"' => ParseString(),
            't' when Take("true") => true,
            'f' when Take("false") => false,
            'n' when Take("null") => null,
            '-' or >= '0' and <= '9' => throw new ProtocolException("numbers are not accepted in Oncefold JSON ingress"),
            _ => throw new ProtocolException("invalid JSON value"),
        };
    }

    private Dictionary<string, object?> ParseObjectValue(int depth)
    {
        if (depth > CanonicalJson.MaxJsonDepth)
            throw new ProtocolException("JSON nesting exceeds the input bound");
        _position++;
        var result = new Dictionary<string, object?>(StringComparer.Ordinal);
        SkipWhitespace();
        if (Take("}")) return result;
        while (true)
        {
            SkipWhitespace();
            if (_position >= _source.Length || _source[_position] != '"')
                throw new ProtocolException("JSON object keys must be strings");
            var key = ParseString();
            if (!result.TryAdd(key, null))
                throw new ProtocolException($"duplicate JSON object key: {key}");
            SkipWhitespace();
            if (!Take(":")) throw new ProtocolException("expected colon after JSON object key");
            result[key] = ParseValue(depth + 1);
            if (result.Count > CanonicalJson.MaxCollectionLength)
                throw new ProtocolException("JSON object exceeds the input bound");
            SkipWhitespace();
            if (Take("}")) return result;
            if (!Take(",")) throw new ProtocolException("expected comma in JSON object");
        }
    }

    private List<object?> ParseArrayValue(int depth)
    {
        if (depth > CanonicalJson.MaxJsonDepth)
            throw new ProtocolException("JSON nesting exceeds the input bound");
        _position++;
        var result = new List<object?>();
        SkipWhitespace();
        if (Take("]")) return result;
        while (true)
        {
            result.Add(ParseValue(depth + 1));
            if (result.Count > CanonicalJson.MaxCollectionLength)
                throw new ProtocolException("JSON array exceeds the input bound");
            SkipWhitespace();
            if (Take("]")) return result;
            if (!Take(",")) throw new ProtocolException("expected comma in JSON array");
        }
    }

    private string ParseString()
    {
        if (!Take("\"")) throw new ProtocolException("expected JSON string");
        var builder = new StringBuilder();
        while (_position < _source.Length)
        {
            var character = _source[_position++];
            if (character == '"')
            {
                ValidateIngressString(builder.ToString());
                return builder.ToString();
            }
            if (character < 0x20)
                throw new ProtocolException("JSON string contains a control character");
            if (character != '\\')
            {
                builder.Append(character);
                continue;
            }
            if (_position >= _source.Length)
                throw new ProtocolException("unterminated JSON escape");
            var escaped = _source[_position++];
            switch (escaped)
            {
                case '"': builder.Append('"'); break;
                case '\\': builder.Append('\\'); break;
                case '/': builder.Append('/'); break;
                case 'b': builder.Append('\b'); break;
                case 'f': builder.Append('\f'); break;
                case 'n': builder.Append('\n'); break;
                case 'r': builder.Append('\r'); break;
                case 't': builder.Append('\t'); break;
                case 'u':
                    var high = ReadHex16();
                    if (high is >= 0xd800 and <= 0xdbff)
                    {
                        if (!Take("\\u")) throw new ProtocolException("unpaired Unicode surrogate");
                        var low = ReadHex16();
                        if (low is < 0xdc00 or > 0xdfff)
                            throw new ProtocolException("unpaired Unicode surrogate");
                        builder.Append((char)high);
                        builder.Append((char)low);
                    }
                    else if (high is >= 0xdc00 and <= 0xdfff)
                    {
                        throw new ProtocolException("unpaired Unicode surrogate");
                    }
                    else
                    {
                        builder.Append((char)high);
                    }
                    break;
                default: throw new ProtocolException("invalid JSON escape");
            }
        }
        throw new ProtocolException("unterminated JSON string");
    }

    private int ReadHex16()
    {
        if (_position + 4 > _source.Length)
            throw new ProtocolException("truncated Unicode escape");
        var value = 0;
        for (var index = 0; index < 4; index++)
        {
            var digit = _source[_position++];
            var parsed = digit switch
            {
                >= '0' and <= '9' => digit - '0',
                >= 'a' and <= 'f' => digit - 'a' + 10,
                >= 'A' and <= 'F' => digit - 'A' + 10,
                _ => -1,
            };
            if (parsed < 0) throw new ProtocolException("invalid Unicode escape");
            value = (value << 4) | parsed;
        }
        return value;
    }

    private static void ValidateIngressString(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsHighSurrogate(character)) index++;
            if (character is '\u2028' or '\u2029')
                throw new ProtocolException("JSON string contains a prohibited line-separator code point");
        }
    }

    private void SkipWhitespace()
    {
        while (_position < _source.Length && _source[_position] is ' ' or '\t' or '\n' or '\r')
            _position++;
    }

    private bool Take(string token)
    {
        if (!_source.AsSpan(_position).StartsWith(token.AsSpan(), StringComparison.Ordinal))
            return false;
        _position += token.Length;
        return true;
    }
}

public sealed record Dependency(string Kind, string Identity, string Digest, bool Required)
{
    public Dictionary<string, object?> AsObject() => new(StringComparer.Ordinal)
    {
        ["kind"] = Kind,
        ["identity"] = Identity,
        ["digest"] = Digest,
        ["required"] = Required,
    };
}

public sealed class ActionModel
{
    public required Dictionary<string, object?> Raw { get; init; }
    public required string Digest { get; init; }
    public required string TrustScope { get; init; }
    public string? AuthorizationScopeDigest { get; init; }
    public required string SideEffectClass { get; init; }
    public required List<Dependency> Dependencies { get; init; }
    public required bool DependencyCompleteness { get; init; }
    public string? ValidatorIdentity { get; init; }
}

public sealed class ReceiptModel
{
    public required Dictionary<string, object?> Raw { get; init; }
    public required string Digest { get; init; }
    public required ActionModel Action { get; init; }
    public required string ResultDigest { get; init; }
    public required string ProducerIdentity { get; init; }
    public required string ReuseClass { get; init; }
    public required string TrustScope { get; init; }
    public required string CacheScope { get; init; }
    public required Dictionary<string, string> Provenance { get; init; }
    public string? RevocationRef { get; init; }
    public string? ValidatorIdentity { get; init; }
    public required List<Dependency> DependencySnapshot { get; init; }
}

public sealed class TrustPolicy
{
    public required HashSet<string> AllowedProducers { get; init; }
    public required HashSet<string> AllowedCacheScopes { get; init; }
    public required Dictionary<string, string> RequiredProvenance { get; init; }
}

public sealed record Decision(string State, string Reason, string ReceiptDigest);

public static class Protocol
{
    public const string ActionSchema = "oncefold.action/1";
    public const string ReceiptSchema = "oncefold.receipt/1";
    private static readonly Regex Digest = new("^[0-9a-f]{64}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex Timestamp = new("^[1-9][0-9]{3}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{6})?Z$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly HashSet<string> SideEffects = new(["READ_ONLY", "LOCAL_WRITE", "EXTERNAL_MUTATION", "UNKNOWN"], StringComparer.Ordinal);
    private static readonly HashSet<string> ReuseClasses = new(["EXACT", "VERIFIED", "ADVISORY", "UNSAFE"], StringComparer.Ordinal);

    public static ActionModel ParseAction(object? value)
    {
        var source = Object(value, "action identity");
        Allowed(source, ["schema_version", "operation_identity", "operation_version", "input_digest", "dependency_completeness"], ["trust_scope", "environment", "dependencies", "side_effect_class", "authorization_scope_digest", "freshness", "validator_identity"], "action identity");
        var schema = Text(Required(source, "schema_version"), "schema_version");
        if (schema != ActionSchema) throw new ProtocolException($"unsupported action schema {schema}");
        var trustScope = Text(source.TryGetValue("trust_scope", out var trust) ? trust : "local", "trust_scope");
        var environment = StringMap(source, "environment");
        var dependencies = Dependencies(source.TryGetValue("dependencies", out var dependencyValue) ? dependencyValue : new List<object?>(), "dependencies");
        var sideEffect = Text(source.TryGetValue("side_effect_class", out var sideEffectValue) ? sideEffectValue : "UNKNOWN", "side_effect_class");
        if (!SideEffects.Contains(sideEffect)) throw new ProtocolException("unknown side effect class");
        var authorization = OptionalDigest(source, "authorization_scope_digest");
        var freshness = StringMap(source, "freshness");
        var completeness = Required(source, "dependency_completeness") as bool?
            ?? throw new ProtocolException("dependency_completeness must be boolean");
        var validator = OptionalText(source, "validator_identity");
        var raw = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema_version"] = schema,
            ["operation_identity"] = Text(Required(source, "operation_identity"), "operation_identity"),
            ["operation_version"] = Text(Required(source, "operation_version"), "operation_version"),
            ["input_digest"] = DigestValue(Required(source, "input_digest"), "input_digest"),
            ["trust_scope"] = trustScope,
            ["environment"] = environment.ToObject(),
            ["dependencies"] = dependencies.Select(item => item.AsObject()).Cast<object?>().ToList(),
            ["side_effect_class"] = sideEffect,
            ["authorization_scope_digest"] = authorization,
            ["freshness"] = freshness.ToObject(),
            ["dependency_completeness"] = completeness,
            ["validator_identity"] = validator,
        };
        return new ActionModel
        {
            Raw = raw,
            Digest = CanonicalJson.Sha256(CanonicalJson.Canonicalize(raw)),
            TrustScope = trustScope,
            AuthorizationScopeDigest = authorization,
            SideEffectClass = sideEffect,
            Dependencies = dependencies,
            DependencyCompleteness = completeness,
            ValidatorIdentity = validator,
        };
    }

    public static ReceiptModel ParseReceipt(object? value, bool allowMissingDigest = false)
    {
        var source = Object(value, "reuse receipt");
        var required = new List<string>(["schema_version", "action", "action_digest", "result_digest", "media_type", "producer_identity", "reuse_class", "created_at", "dependency_snapshot", "trust_scope", "cache_scope"]);
        if (!allowMissingDigest) required.Add("receipt_digest");
        Allowed(source, required, ["result_reference", "provenance", "revocation_ref", "validator_identity", "execution_metadata", "economics", "receipt_digest"], "reuse receipt");
        var schema = Text(Required(source, "schema_version"), "schema_version");
        if (schema != ReceiptSchema) throw new ProtocolException($"unsupported receipt schema {schema}");
        var action = ParseAction(Required(source, "action"));
        var actionDigest = DigestValue(Required(source, "action_digest"), "action_digest");
        if (actionDigest != action.Digest) throw new ProtocolException("receipt action digest mismatch");
        var resultDigest = DigestValue(Required(source, "result_digest"), "result_digest");
        var mediaType = Text(Required(source, "media_type"), "media_type");
        var producer = Text(Required(source, "producer_identity"), "producer_identity");
        var reuseClass = Text(Required(source, "reuse_class"), "reuse_class");
        if (!ReuseClasses.Contains(reuseClass)) throw new ProtocolException("unknown reuse class");
        var createdAt = CanonicalTimestamp(Required(source, "created_at"));
        var snapshot = Dependencies(Required(source, "dependency_snapshot"), "dependency_snapshot");
        var trustScope = Text(Required(source, "trust_scope"), "trust_scope");
        var cacheScope = Text(Required(source, "cache_scope"), "cache_scope");
        var resultReference = OptionalText(source, "result_reference");
        var provenance = StringMap(source, "provenance");
        var revocation = OptionalText(source, "revocation_ref");
        var validator = OptionalText(source, "validator_identity");
        var execution = StringMap(source, "execution_metadata");
        var economics = StringMap(source, "economics");
        var raw = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema_version"] = schema,
            ["action"] = action.Raw,
            ["action_digest"] = action.Digest,
            ["result_digest"] = resultDigest,
            ["result_reference"] = resultReference,
            ["media_type"] = mediaType,
            ["producer_identity"] = producer,
            ["reuse_class"] = reuseClass,
            ["created_at"] = createdAt,
            ["dependency_snapshot"] = snapshot.Select(item => item.AsObject()).Cast<object?>().ToList(),
            ["provenance"] = provenance.ToObject(),
            ["trust_scope"] = trustScope,
            ["cache_scope"] = cacheScope,
            ["revocation_ref"] = revocation,
            ["validator_identity"] = validator,
            ["execution_metadata"] = execution.ToObject(),
            ["economics"] = economics.ToObject(),
        };
        var digest = CanonicalJson.Sha256(CanonicalJson.Canonicalize(raw));
        if (!allowMissingDigest && DigestValue(Required(source, "receipt_digest"), "receipt_digest") != digest)
            throw new ProtocolException("receipt digest mismatch");
        return new ReceiptModel
        {
            Raw = raw,
            Digest = digest,
            Action = action,
            ResultDigest = resultDigest,
            ProducerIdentity = producer,
            ReuseClass = reuseClass,
            TrustScope = trustScope,
            CacheScope = cacheScope,
            Provenance = provenance.Values,
            RevocationRef = revocation,
            ValidatorIdentity = validator,
            DependencySnapshot = snapshot,
        };
    }

    public static TrustPolicy ParseTrustPolicy(object? value)
    {
        var source = Object(value, "trust policy");
        var producers = Strings(source.TryGetValue("allowed_producers", out var producerValue) ? producerValue : new List<object?>(), "allowed_producers");
        var scopes = Strings(source.TryGetValue("allowed_cache_scopes", out var scopeValue) ? scopeValue : new List<object?>(), "allowed_cache_scopes");
        var provenance = StringMap(source, "required_provenance");
        return new TrustPolicy
        {
            AllowedProducers = producers.ToHashSet(StringComparer.Ordinal),
            AllowedCacheScopes = scopes.ToHashSet(StringComparer.Ordinal),
            RequiredProvenance = provenance.Values,
        };
    }

    public static Dictionary<string, object?> MaterializeReceipt(Dictionary<string, object?> baseReceipt, Dictionary<string, object?> patch, bool recompute)
    {
        var result = (Dictionary<string, object?>)CanonicalJson.Clone(baseReceipt)!;
        foreach (var pair in patch) result[pair.Key] = CanonicalJson.Clone(pair.Value);
        if (recompute)
        {
            result.Remove("receipt_digest");
            var parsed = ParseReceipt(result, allowMissingDigest: true);
            result["receipt_digest"] = parsed.Digest;
        }
        return result;
    }

    public static Decision Evaluate(ActionModel action, ReceiptModel receipt, bool revoked, string? availableResultDigest, bool hasValidatorResult, bool validatorResult, TrustPolicy policy)
    {
        var digest = receipt.Digest;
        if (revoked || receipt.RevocationRef is not null) return new("REVOKED", "receipt revoked", digest);
        if (action.TrustScope != receipt.TrustScope || action.TrustScope != receipt.Action.TrustScope || action.AuthorizationScopeDigest != receipt.Action.AuthorizationScopeDigest)
            return new("SCOPE_MISMATCH", "scope mismatch", digest);
        if (action.SideEffectClass != "READ_ONLY" || receipt.Action.SideEffectClass != "READ_ONLY")
            return new("UNSAFE", "non-read-only action is not reusable", digest);
        if (receipt.ReuseClass == "UNSAFE") return new("UNSAFE", "receipt is marked unsafe", digest);
        if (!action.DependencyCompleteness || !receipt.Action.DependencyCompleteness)
            return new("UNKNOWN", "dependency declaration is incomplete", digest);
        if (action.Digest != receipt.Action.Digest) return new("STALE", "action identity mismatch", digest);
        if (CanonicalJson.Canonicalize(action.Dependencies.Select(item => item.AsObject()).Cast<object?>().ToList()) != CanonicalJson.Canonicalize(receipt.DependencySnapshot.Select(item => item.AsObject()).Cast<object?>().ToList()))
            return new("STALE", "dependency snapshot mismatch", digest);
        if (availableResultDigest is not null && (!Digest.IsMatch(availableResultDigest) || availableResultDigest != receipt.ResultDigest))
            return new("UNKNOWN", "result digest mismatch", digest);
        if (receipt.ReuseClass is "EXACT" or "VERIFIED" && !Admits(receipt, policy))
            return new("UNKNOWN", "receipt producer, cache scope, or provenance is not trusted", digest);
        if (receipt.ReuseClass == "EXACT") return new("REUSABLE_EXACT", "identity and dependencies match", digest);
        if (receipt.ReuseClass == "VERIFIED")
        {
            if (receipt.ValidatorIdentity is null || receipt.ValidatorIdentity != action.ValidatorIdentity)
                return new("REQUIRES_VALIDATION", "matching validator identity required", digest);
            if (!hasValidatorResult) return new("REQUIRES_VALIDATION", "current validator required", digest);
            return validatorResult
                ? new("REUSABLE_EXACT", "current validator passed", digest)
                : new("STALE", "current validator rejected receipt", digest);
        }
        if (receipt.ReuseClass == "ADVISORY") return new("ADVISORY_ONLY", "context only; not authoritative", digest);
        return new("UNSAFE", "unknown reuse class", digest);
    }

    public static string CanonicalTimestamp(object? value)
    {
        var text = CanonicalJson.Text(value, "created_at");
        if (!Timestamp.IsMatch(text)) throw new ProtocolException("created_at must be RFC 3339 UTC with Z and optional six-digit fractions");
        var formats = new[] { "yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'" };
        if (!DateTimeOffset.TryParseExact(text, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            throw new ProtocolException("created_at is not a valid timestamp");
        return parsed.Ticks % TimeSpan.TicksPerSecond == 0
            ? parsed.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
            : parsed.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
    }

    private static bool Admits(ReceiptModel receipt, TrustPolicy policy)
    {
        if (!policy.AllowedProducers.Contains(receipt.ProducerIdentity) || !policy.AllowedCacheScopes.Contains(receipt.CacheScope)) return false;
        return policy.RequiredProvenance.All(pair => receipt.Provenance.TryGetValue(pair.Key, out var actual) && actual == pair.Value);
    }

    private static Dictionary<string, object?> Object(object? value, string name) => value as Dictionary<string, object?> ?? throw new ProtocolException($"{name} must be an object");

    private static object? Required(Dictionary<string, object?> source, string name) => source.TryGetValue(name, out var value) ? value : throw new ProtocolException($"missing required field {name}");

    private static string Text(object? value, string name, bool required = true, int maxLength = CanonicalJson.MaxStringLength) => CanonicalJson.Text(value, name, required, maxLength);

    private static string? OptionalText(Dictionary<string, object?> source, string name) => !source.TryGetValue(name, out var value) || value is null ? null : Text(value, name, required: false);

    private static string? OptionalDigest(Dictionary<string, object?> source, string name) => !source.TryGetValue(name, out var value) || value is null ? null : DigestValue(value, name);

    private static string DigestValue(object? value, string name)
    {
        var text = Text(value, name);
        if (!Digest.IsMatch(text)) throw new ProtocolException($"{name} must be a lowercase SHA-256 digest");
        return text;
    }

    private static void Allowed(Dictionary<string, object?> source, IEnumerable<string> required, IEnumerable<string> optional, string name)
    {
        var known = required.Concat(optional).ToHashSet(StringComparer.Ordinal);
        foreach (var field in required) if (!source.ContainsKey(field)) throw new ProtocolException($"{name} is missing {field}");
        foreach (var field in source.Keys) if (!known.Contains(field)) throw new ProtocolException($"{name} contains unknown field {field}");
    }

    private static StringMapResult StringMap(Dictionary<string, object?> source, string name)
    {
        if (!source.TryGetValue(name, out var value)) return new StringMapResult();
        var map = Object(value, name);
        if (map.Count > CanonicalJson.MaxCollectionLength) throw new ProtocolException($"{name} exceeds collection bound");
        var normalized = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in map)
        {
            var key = Text(pair.Key, $"{name} key");
            if (!normalized.TryAdd(key, Text(pair.Value, $"{name}.{key}"))) throw new ProtocolException($"{name} keys collide after NFC normalization");
        }
        return new StringMapResult(normalized);
    }

    private static List<string> Strings(object? value, string name)
    {
        if (value is not List<object?> list || list.Count > CanonicalJson.MaxCollectionLength) throw new ProtocolException($"{name} must be a bounded array");
        return list.Select(item => Text(item, name)).ToList();
    }

    private static List<Dependency> Dependencies(object? value, string name)
    {
        if (value is not List<object?> list || list.Count > CanonicalJson.MaxCollectionLength) throw new ProtocolException($"{name} must be a bounded array");
        var parsed = new List<Dependency>();
        foreach (var item in list)
        {
            var source = Object(item, "dependency");
            Allowed(source, ["kind", "identity", "digest"], ["required"], "dependency");
            var required = source.TryGetValue("required", out var requiredValue) ? requiredValue as bool? : true;
            if (required is null) throw new ProtocolException("dependency.required must be boolean");
            parsed.Add(new Dependency(Text(Required(source, "kind"), "dependency.kind", maxLength: 128), Text(Required(source, "identity"), "dependency.identity"), DigestValue(Required(source, "digest"), "dependency.digest"), required.Value));
        }
        var duplicate = parsed.GroupBy(item => $"{item.Kind}\u0000{item.Identity}", StringComparer.Ordinal).FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null) throw new ProtocolException($"{name} contains duplicate dependency identity");
        return parsed.OrderBy(item => item.Kind, Utf8Comparer.Instance).ThenBy(item => item.Identity, Utf8Comparer.Instance).ThenBy(item => item.Digest, Utf8Comparer.Instance).ToList();
    }

    private sealed class Utf8Comparer : IComparer<string>
    {
        public static Utf8Comparer Instance { get; } = new();
        public int Compare(string? x, string? y) => CanonicalJson.CompareUtf8(x ?? string.Empty, y ?? string.Empty);
    }

    private sealed class StringMapResult
    {
        public Dictionary<string, string> Values { get; }
        public StringMapResult() : this(new Dictionary<string, string>(StringComparer.Ordinal)) { }
        public StringMapResult(Dictionary<string, string> values) => Values = values;
        public Dictionary<string, object?> ToObject() => Values.ToDictionary(pair => pair.Key, pair => (object?)pair.Value, StringComparer.Ordinal);
    }
}
