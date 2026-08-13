using System.Text;
using Oncefold.DotNet;

if (args.Length != 2 || !string.Equals(args[0], "conformance", StringComparison.Ordinal))
{
    Console.Error.WriteLine("usage: dotnet run -- conformance <path-to-vectors.json>");
    return 2;
}

try
{
    var path = Path.GetFullPath(args[1]);
    var corpus = WireParser.ParseObject(File.ReadAllBytes(path));
    var result = Conformance.Run(corpus);
    Console.WriteLine($"{{\"implementation\":\"dotnet-independent\",\"total\":{result.Total},\"passed\":{result.Passed},\"failures\":{CanonicalJson.Canonicalize(result.Failures)}}}");
    return result.Passed == result.Total ? 0 : 1;
}
catch (Exception exception) when (exception is ProtocolException or IOException or UnauthorizedAccessException)
{
    Console.Error.WriteLine($"conformance error: {exception.Message}");
    return 1;
}

internal sealed record ConformanceResult(int Total, int Passed, List<object?> Failures);

internal static class Conformance
{
    public static ConformanceResult Run(Dictionary<string, object?> corpus)
    {
        var failures = new List<object?>();
        var total = 0;

        CheckCanonicalization(corpus["canonicalization"], corpus, failures);
        foreach (var item in Array(corpus, "timestamp_cases"))
            CheckTimestamps(item, corpus, failures);
        foreach (var item in Array(corpus, "raw_json_cases"))
            CheckRawJson(item, corpus, failures);
        foreach (var item in Array(corpus, "cases"))
        {
            total++;
            CheckDecisions(item, corpus, failures);
        }
        CheckAdversarial(failures);

        return new ConformanceResult(total, Math.Max(0, total - failures.Count), failures);
    }

    private static void Check(
        Dictionary<string, object?> corpus,
        string name,
        List<object?> failures,
        ref int total,
        ref int passed,
        Func<object?, Dictionary<string, object?>, List<object?>, bool> checker)
    {
        if (!corpus.TryGetValue(name, out var value))
            throw new ProtocolException($"conformance corpus is missing {name}");
        if (name == "canonicalization")
        {
            total++;
            if (checker(value, corpus, failures)) passed++;
            return;
        }
        if (value is not List<object?> list)
            throw new ProtocolException($"conformance corpus field {name} must be an array");
        foreach (var item in list)
        {
            total++;
            if (checker(item, corpus, failures)) passed++;
        }
    }

    private static bool CheckCanonicalization(object? value, Dictionary<string, object?> corpus, List<object?> failures)
    {
        var section = Object(value, "canonicalization");
        var decomposed = Text(section, "decomposed");
        var composed = Text(section, "composed");
        var equivalent = Bool(section, "equivalent");
        var keyOrder = Object(section["utf8_key_order"], "utf8_key_order");
        var keyOrderDigest = Text(section, "utf8_key_order_digest");
        var prototype = Object(section["prototype_key_object"], "prototype_key_object");
        var prototypeDigest = Text(section, "prototype_key_object_digest");
        var nfc = CanonicalJson.Canonicalize(decomposed) == CanonicalJson.Canonicalize(composed);
        var keyOk = CanonicalJson.Sha256(CanonicalJson.Canonicalize(keyOrder)) == keyOrderDigest;
        var prototypeOk = CanonicalJson.Sha256(CanonicalJson.Canonicalize(prototype)) == prototypeDigest;
        var ok = equivalent && nfc && keyOk && prototypeOk;
        if (!ok) AddFailure(failures, "canonicalization", $"digest or NFC mismatch (equivalent={equivalent}, nfc={nfc}, key={keyOk}, prototype={prototypeOk})");
        return ok;
    }

    private static bool CheckTimestamps(object? value, Dictionary<string, object?> _, List<object?> failures)
    {
        var item = Object(value, "timestamp case");
        var input = Text(item, "value");
        var accepted = Bool(item, "accepted");
        try
        {
            var canonical = Protocol.CanonicalTimestamp(input);
            var expected = item.TryGetValue("canonical", out var expectedValue) ? CanonicalJson.Text(expectedValue, "canonical") : null;
            var ok = accepted && expected is not null && canonical == expected;
            if (!ok) AddFailure(failures, Text(item, "id"), "timestamp result mismatch");
            return ok;
        }
        catch (ProtocolException)
        {
            var ok = !accepted;
            if (!ok) AddFailure(failures, Text(item, "id"), "timestamp was unexpectedly rejected");
            return ok;
        }
    }

    private static bool CheckRawJson(object? value, Dictionary<string, object?> _, List<object?> failures)
    {
        var item = Object(value, "raw JSON case");
        var identifier = Text(item, "id");
        var source = Text(item, "json");
        var accepted = Bool(item, "accepted");
        try
        {
            _ = WireParser.ParseObject(Encoding.UTF8.GetBytes(source));
            var ok = accepted;
            if (!ok) AddFailure(failures, identifier, "raw JSON was unexpectedly accepted");
            return ok;
        }
        catch (ProtocolException)
        {
            var ok = !accepted;
            if (!ok) AddFailure(failures, identifier, "raw JSON was unexpectedly rejected");
            return ok;
        }
    }

    private static bool CheckDecisions(object? value, Dictionary<string, object?> corpus, List<object?> failures)
    {
        var item = Object(value, "decision case");
        var identifier = Text(item, "id");
        try
        {
            var baseSection = Object(corpus["base"], "base");
            var actionSource = Object(baseSection["action"], "base.action");
            var receiptSource = Object(baseSection["receipt"], "base.receipt");
            var actionPatch = OptionalObject(item, "action_patch");
            var receiptPatch = OptionalObject(item, "receipt_patch");
            var actionMaterialized = Merge(actionSource, actionPatch);
            var receiptMaterialized = Protocol.MaterializeReceipt(receiptSource, receiptPatch, BoolOrDefault(item, "recompute_receipt_digest", false));
            var action = Protocol.ParseAction(actionMaterialized);
            var receipt = Protocol.ParseReceipt(receiptMaterialized);
            var policy = Protocol.ParseTrustPolicy(corpus["trust_policy"]);
            var revoked = BoolOrDefault(item, "revoked", false);
            var available = item.TryGetValue("available_result_digest", out var availableValue) && availableValue is not null ? CanonicalJson.Text(availableValue, "available_result_digest") : null;
            var hasValidator = item.ContainsKey("validator_result");
            var validatorResult = BoolOrDefault(item, "validator_result", false);
            var decision = Protocol.Evaluate(action, receipt, revoked, available, hasValidator, validatorResult, policy);
            var expected = Text(item, "expected_state");
            var ok = decision.State == expected;
            if (!ok) AddFailure(failures, identifier, $"expected {expected}, got {decision.State}");
            return ok;
        }
        catch (ProtocolException)
        {
            var expected = Text(item, "expected_state");
            var ok = expected == "UNKNOWN";
            if (!ok) AddFailure(failures, identifier, $"expected {expected}, got UNKNOWN");
            return ok;
        }
    }

    private static Dictionary<string, object?> Merge(Dictionary<string, object?> source, Dictionary<string, object?> patch)
    {
        var result = (Dictionary<string, object?>)CanonicalJson.Clone(source)!;
        foreach (var pair in patch) result[pair.Key] = CanonicalJson.Clone(pair.Value);
        return result;
    }

    private static Dictionary<string, object?> OptionalObject(Dictionary<string, object?> source, string name)
        => !source.TryGetValue(name, out var value) || value is null ? new Dictionary<string, object?>(StringComparer.Ordinal) : Object(value, name);

    private static Dictionary<string, object?> Object(object? value, string name)
        => value as Dictionary<string, object?> ?? throw new ProtocolException($"{name} must be an object");

    private static List<object?> Array(Dictionary<string, object?> source, string name)
        => source.TryGetValue(name, out var value) && value is List<object?> list ? list : throw new ProtocolException($"{name} must be an array");

    private static string Text(Dictionary<string, object?> source, string name)
        => source.TryGetValue(name, out var value) ? CanonicalJson.Text(value, name) : throw new ProtocolException($"missing {name}");

    private static bool Bool(Dictionary<string, object?> source, string name)
        => source.TryGetValue(name, out var value) && value is bool result ? result : throw new ProtocolException($"{name} must be boolean");

    private static bool BoolOrDefault(Dictionary<string, object?> source, string name, bool fallback)
        => !source.TryGetValue(name, out var value) || value is null ? fallback : Bool(source, name);

    private static void AddFailure(List<object?> failures, string identifier, string message)
        => failures.Add(new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = identifier, ["message"] = message });

    private static void CheckAdversarial(List<object?> failures)
    {
        ExpectProtocolFailure(
            failures,
            "canonical-nfc-key-collision",
            () => CanonicalJson.Canonicalize(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["cafe\u0301"] = "first",
                ["café"] = "second",
            }));
        ExpectProtocolFailure(
            failures,
            "canonical-depth-bound",
            () =>
            {
                object? value = "ok";
                for (var index = 0; index < CanonicalJson.MaxCanonicalDepth + 1; index++)
                    value = new List<object?> { value };
                _ = CanonicalJson.Canonicalize(value);
            });
        ExpectProtocolFailure(
            failures,
            "invalid-utf8-ingress",
            () => _ = WireParser.ParseObject(new byte[] { 0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d }));
        ExpectProtocolFailure(
            failures,
            "ingress-size-bound",
            () => _ = WireParser.ParseObject(new byte[CanonicalJson.MaxJsonBytes + 1]));
    }

    private static void ExpectProtocolFailure(List<object?> failures, string identifier, Action action)
    {
        try
        {
            action();
            AddFailure(failures, identifier, "adversarial input was accepted");
        }
        catch (ProtocolException)
        {
            // Expected fail-closed result.
        }
    }
}
