// Independent Oncefold Go consumer.
// It is implemented from the public protocol, schemas, and JSON vectors.
package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	ActionSchema  = "oncefold.action/1"
	ReceiptSchema = "oncefold.receipt/1"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var timestampPattern = regexp.MustCompile(`^[1-9][0-9]{3}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{6})?Z$`)

const (
	maxJSONBytes = 1_048_576
	maxJSONDepth = 32
)

func containsForbiddenCodePoint(value string) bool {
	return strings.ContainsRune(value, '\u2028') || strings.ContainsRune(value, '\u2029')
}

type Action struct {
	Raw                      map[string]any
	Digest                   string
	TrustScope               string
	AuthorizationScopeDigest *string
	SideEffectClass          string
	Dependencies             []map[string]any
	DependencyCompleteness   bool
	ValidatorIdentity        *string
}

type Receipt struct {
	Raw                map[string]any
	Digest             string
	Action             Action
	ResultDigest       string
	ReuseClass         string
	TrustScope         string
	RevocationRef      *string
	ValidatorIdentity  *string
	DependencySnapshot []map[string]any
	CacheScope         string
	ProducerIdentity   string
	Provenance         map[string]any
}

type TrustPolicy struct {
	AllowedProducers   []string          `json:"allowed_producers"`
	AllowedCacheScopes []string          `json:"allowed_cache_scopes"`
	RequiredProvenance map[string]string `json:"required_provenance"`
}

type Decision struct {
	State         string `json:"state"`
	Reason        string `json:"reason"`
	ReceiptDigest string `json:"receipt_digest,omitempty"`
}

const (
	ReusableExact      = "REUSABLE_EXACT"
	RequiresValidation = "REQUIRES_VALIDATION"
	AdvisoryOnly       = "ADVISORY_ONLY"
	Revoked            = "REVOKED"
	Stale              = "STALE"
	ScopeMismatch      = "SCOPE_MISMATCH"
	Unsafe             = "UNSAFE"
	Unknown            = "UNKNOWN"
)

func canonical(value any) ([]byte, error) {
	normalized, err := normalize(value, 0)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

func normalize(value any, depth int) (any, error) {
	if depth > 16 {
		return nil, fmt.Errorf("canonical value is too deeply nested")
	}
	switch typed := value.(type) {
	case nil, bool:
		return typed, nil
	case string:
		if !utf8.ValidString(typed) {
			return nil, fmt.Errorf("canonical string is not valid UTF-8")
		}
		if containsForbiddenCodePoint(typed) {
			return nil, fmt.Errorf("canonical string contains a prohibited line-separator code point")
		}
		if utf8.RuneCountInString(typed) > 4096 {
			return nil, fmt.Errorf("canonical string exceeds bound")
		}
		for _, character := range typed {
			if character < 0x20 {
				return nil, fmt.Errorf("canonical string contains control character")
			}
		}
		return norm.NFC.String(typed), nil
	case json.Number, float64:
		return nil, fmt.Errorf("numbers are not canonicalizable; supply an opaque input digest")
	case []any:
		if len(typed) > 256 {
			return nil, fmt.Errorf("canonical array exceeds bound")
		}
		result := make([]any, len(typed))
		for index, item := range typed {
			clean, err := normalize(item, depth+1)
			if err != nil {
				return nil, err
			}
			result[index] = clean
		}
		return result, nil
	case map[string]any:
		if len(typed) > 256 {
			return nil, fmt.Errorf("canonical object exceeds bound")
		}
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			if !utf8.ValidString(key) {
				return nil, fmt.Errorf("canonical object key is not valid UTF-8")
			}
			cleanKey := norm.NFC.String(key)
			if containsForbiddenCodePoint(cleanKey) {
				return nil, fmt.Errorf("canonical object key contains a prohibited line-separator code point")
			}
			if utf8.RuneCountInString(cleanKey) > 4096 {
				return nil, fmt.Errorf("canonical object key exceeds bound")
			}
			for _, character := range cleanKey {
				if character < 0x20 {
					return nil, fmt.Errorf("canonical object key contains control character")
				}
			}
			if _, exists := result[cleanKey]; exists {
				return nil, fmt.Errorf("canonical key collision")
			}
			clean, err := normalize(item, depth+1)
			if err != nil {
				return nil, err
			}
			result[cleanKey] = clean
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported canonical value %T", value)
	}
}

func SHA256Canonical(value any) (string, error) {
	encoded, err := canonical(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validateJSONText(data []byte) error {
	if len(data) > maxJSONBytes {
		return fmt.Errorf("JSON input exceeds %d bytes", maxJSONBytes)
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("JSON input is not valid UTF-8")
	}
	depth := 0
	inString := false
	escaped := false
	for index := 0; index < len(data); index++ {
		character := data[index]
		if inString {
			if escaped {
				if character == 'u' {
					if index+4 >= len(data) {
						return fmt.Errorf("truncated Unicode escape")
					}
					code, err := strconv.ParseUint(string(data[index+1:index+5]), 16, 16)
					if err != nil {
						return fmt.Errorf("invalid Unicode escape")
					}
					if code >= 0xDC00 && code <= 0xDFFF {
						return fmt.Errorf("unpaired Unicode surrogate")
					}
					if code >= 0xD800 && code <= 0xDBFF {
						if index+11 >= len(data) || data[index+5] != '\\' || data[index+6] != 'u' {
							return fmt.Errorf("unpaired Unicode surrogate")
						}
						low, err := strconv.ParseUint(string(data[index+7:index+11]), 16, 16)
						if err != nil || low < 0xDC00 || low > 0xDFFF {
							return fmt.Errorf("unpaired Unicode surrogate")
						}
						index += 10
					} else {
						index += 4
					}
				}
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
			} else if character == '"' {
				inString = false
			}
			continue
		}
		if character == '"' {
			inString = true
		} else if character == '{' || character == '[' {
			depth++
			if depth > maxJSONDepth {
				return fmt.Errorf("JSON nesting exceeds the input bound")
			}
		} else if character == '}' || character == ']' {
			depth--
			if depth < 0 {
				return fmt.Errorf("malformed JSON nesting")
			}
		}
	}
	return nil
}

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch typed := token.(type) {
	case json.Delim:
		if depth > maxJSONDepth {
			return nil, fmt.Errorf("JSON nesting exceeds the input bound")
		}
		switch typed {
		case '{':
			result := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("JSON object key must be a string")
				}
				if containsForbiddenCodePoint(key) {
					return nil, fmt.Errorf("JSON object key contains a prohibited line-separator code point")
				}
				if _, exists := result[key]; exists {
					return nil, fmt.Errorf("duplicate JSON object key: %s", key)
				}
				value, err := decodeValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				result[key] = value
				if len(result) > 256 {
					return nil, fmt.Errorf("JSON object exceeds the input bound")
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("malformed JSON object")
			}
			return result, nil
		case '[':
			result := []any{}
			for decoder.More() {
				value, err := decodeValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				result = append(result, value)
				if len(result) > 256 {
					return nil, fmt.Errorf("JSON array exceeds the input bound")
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("malformed JSON array")
			}
			return result, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter")
		}
	case json.Number:
		return nil, fmt.Errorf("numbers are not accepted in Oncefold JSON ingress")
	case string:
		if containsForbiddenCodePoint(typed) {
			return nil, fmt.Errorf("JSON string contains a prohibited line-separator code point")
		}
		return typed, nil
	case bool, nil:
		return typed, nil
	default:
		return nil, fmt.Errorf("unsupported JSON value %T", token)
	}
}

// ParseJSON parses one bounded JSON document while rejecting duplicate keys,
// numbers, excessive nesting, and invalid Unicode surrogate sequences.
func ParseJSON(data []byte) (any, error) {
	if err := validateJSONText(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 1)
	if err != nil {
		return nil, err
	}
	if extra, err := decoder.Token(); err != io.EOF || extra != nil {
		return nil, fmt.Errorf("trailing JSON")
	}
	return value, nil
}

func decodeObject(data []byte) (map[string]any, error) {
	value, err := ParseJSON(data)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected object")
	}
	return object, nil
}

func allowed(value map[string]any, required, optional []string, name string) error {
	known := make(map[string]bool, len(required)+len(optional))
	for _, key := range append(required, optional...) {
		known[key] = true
	}
	for _, key := range required {
		if _, exists := value[key]; !exists {
			return fmt.Errorf("%s missing %s", name, key)
		}
	}
	for key := range value {
		if !known[key] {
			return fmt.Errorf("%s contains unknown field %s", name, key)
		}
	}
	return nil
}

func stringValue(value any, name string, optional bool, maxLengths ...int) (string, *string, error) {
	if value == nil && optional {
		return "", nil, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", nil, fmt.Errorf("%s must be a bounded string", name)
	}
	if !utf8.ValidString(text) {
		return "", nil, fmt.Errorf("%s must be a bounded string", name)
	}
	normalized := norm.NFC.String(text)
	maxLength := 4096
	if len(maxLengths) > 0 {
		maxLength = maxLengths[0]
	}
	if (!optional && normalized == "") || !utf8.ValidString(normalized) || containsForbiddenCodePoint(normalized) || utf8.RuneCountInString(normalized) > maxLength {
		return "", nil, fmt.Errorf("%s must be a bounded string", name)
	}
	for _, character := range normalized {
		if character < 0x20 {
			return "", nil, fmt.Errorf("%s contains a control character", name)
		}
	}
	if optional {
		return "", &normalized, nil
	}
	return normalized, nil, nil
}

func requiredDigest(value any, name string) (string, error) {
	text, _, err := stringValue(value, name, false)
	if err != nil || !digestPattern.MatchString(text) {
		return "", fmt.Errorf("%s must be a lowercase SHA-256 digest", name)
	}
	return text, nil
}

func stringMap(value any, name string) (map[string]any, error) {
	source, ok := value.(map[string]any)
	if !ok || len(source) > 256 {
		return nil, fmt.Errorf("%s must be a bounded map", name)
	}
	result := make(map[string]any, len(source))
	for key, item := range source {
		normalizedKey, _, err := stringValue(key, name+" key", false)
		if err != nil {
			return nil, err
		}
		if _, exists := result[normalizedKey]; exists {
			return nil, fmt.Errorf("%s keys collide after NFC normalization", name)
		}
		text, _, err := stringValue(item, name+"."+normalizedKey, false)
		if err != nil {
			return nil, err
		}
		result[normalizedKey] = text
	}
	return result, nil
}

func parseDependency(value any) (map[string]any, error) {
	source, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("dependency must be an object")
	}
	if err := allowed(source, []string{"kind", "identity", "digest"}, []string{"required"}, "dependency"); err != nil {
		return nil, err
	}
	kind, _, err := stringValue(source["kind"], "dependency.kind", false, 128)
	if err != nil {
		return nil, err
	}
	identity, _, err := stringValue(source["identity"], "dependency.identity", false)
	if err != nil {
		return nil, err
	}
	digest, err := requiredDigest(source["digest"], "dependency.digest")
	if err != nil {
		return nil, err
	}
	required := true
	if raw, exists := source["required"]; exists {
		var ok bool
		required, ok = raw.(bool)
		if !ok {
			return nil, fmt.Errorf("dependency.required must be boolean")
		}
	}
	return map[string]any{"kind": kind, "identity": identity, "digest": digest, "required": required}, nil
}

func parseDependencies(value any, name string) ([]map[string]any, error) {
	items, ok := value.([]any)
	if !ok || len(items) > 256 {
		return nil, fmt.Errorf("%s must be a bounded array", name)
	}
	result := make([]map[string]any, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		parsed, err := parseDependency(item)
		if err != nil {
			return nil, err
		}
		id := parsed["kind"].(string) + "\x00" + parsed["identity"].(string)
		if seen[id] {
			return nil, fmt.Errorf("%s contains duplicate dependency identity", name)
		}
		seen[id] = true
		result = append(result, parsed)
	}
	sort.Slice(result, func(left, right int) bool {
		leftKind := result[left]["kind"].(string)
		rightKind := result[right]["kind"].(string)
		if leftKind != rightKind {
			return leftKind < rightKind
		}
		leftIdentity := result[left]["identity"].(string)
		rightIdentity := result[right]["identity"].(string)
		if leftIdentity != rightIdentity {
			return leftIdentity < rightIdentity
		}
		return result[left]["digest"].(string) < result[right]["digest"].(string)
	})
	return result, nil
}

func optionalDigest(value any, name string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	digest, err := requiredDigest(value, name)
	return &digest, err
}

func optionalText(value any, name string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	_, text, err := stringValue(value, name, true)
	return text, err
}

// CanonicalTimestamp accepts only UTC RFC 3339 values with optional six-digit
// fractions and normalizes an all-zero fraction away.
func CanonicalTimestamp(value string) (string, error) {
	if !timestampPattern.MatchString(value) {
		return "", fmt.Errorf("created_at must be RFC 3339 UTC with Z and optional six-digit fractions")
	}
	base := value[:19] + "Z"
	if _, err := time.Parse("2006-01-02T15:04:05Z", base); err != nil {
		return "", err
	}
	if len(value) == 20 || strings.Trim(value[20:26], "0") == "" {
		return base, nil
	}
	return value, nil
}

func admits(receipt Receipt, policy TrustPolicy) bool {
	producerAllowed := false
	for _, producer := range policy.AllowedProducers {
		if norm.NFC.String(producer) == receipt.ProducerIdentity {
			producerAllowed = true
			break
		}
	}
	if !producerAllowed {
		return false
	}
	scopeAllowed := false
	for _, scope := range policy.AllowedCacheScopes {
		if norm.NFC.String(scope) == receipt.CacheScope {
			scopeAllowed = true
			break
		}
	}
	if !scopeAllowed {
		return false
	}
	for key, value := range policy.RequiredProvenance {
		if receipt.Provenance[norm.NFC.String(key)] != norm.NFC.String(value) {
			return false
		}
	}
	return true
}

func ParseAction(source map[string]any) (Action, error) {
	if err := allowed(source, []string{"schema_version", "operation_identity", "operation_version", "input_digest", "dependency_completeness"}, []string{"trust_scope", "environment", "dependencies", "side_effect_class", "authorization_scope_digest", "freshness", "validator_identity"}, "action identity"); err != nil {
		return Action{}, err
	}
	schema, _, err := stringValue(source["schema_version"], "schema_version", false)
	if err != nil || schema != ActionSchema {
		return Action{}, fmt.Errorf("unsupported action schema")
	}
	operationIdentity, _, err := stringValue(source["operation_identity"], "operation_identity", false)
	if err != nil {
		return Action{}, err
	}
	operationVersion, _, err := stringValue(source["operation_version"], "operation_version", false)
	if err != nil {
		return Action{}, err
	}
	inputDigest, err := requiredDigest(source["input_digest"], "input_digest")
	if err != nil {
		return Action{}, err
	}
	trustScope := "local"
	if raw, exists := source["trust_scope"]; exists {
		trustScope, _, err = stringValue(raw, "trust_scope", false)
		if err != nil {
			return Action{}, err
		}
	}
	environmentValue := any(map[string]any{})
	if raw, exists := source["environment"]; exists {
		environmentValue = raw
	}
	environment, err := stringMap(environmentValue, "environment")
	if err != nil {
		return Action{}, err
	}
	dependencyArrayValue := any([]any{})
	if raw, exists := source["dependencies"]; exists {
		dependencyArrayValue = raw
	}
	dependencyArray, err := defaultArray(dependencyArrayValue)
	if err != nil {
		return Action{}, err
	}
	parsedDependencies, err := parseDependencies(dependencyArray, "dependencies")
	if err != nil {
		return Action{}, err
	}
	sideEffect := "UNKNOWN"
	if raw, exists := source["side_effect_class"]; exists {
		sideEffect, _, err = stringValue(raw, "side_effect_class", false)
		if err != nil || !map[string]bool{"READ_ONLY": true, "LOCAL_WRITE": true, "EXTERNAL_MUTATION": true, "UNKNOWN": true}[sideEffect] {
			return Action{}, fmt.Errorf("unknown side effect class")
		}
	}
	authorizationDigest, err := optionalDigest(source["authorization_scope_digest"], "authorization_scope_digest")
	if err != nil {
		return Action{}, err
	}
	freshnessValue := any(map[string]any{})
	if raw, exists := source["freshness"]; exists {
		freshnessValue = raw
	}
	freshness, err := stringMap(freshnessValue, "freshness")
	if err != nil {
		return Action{}, err
	}
	complete := false
	if raw, exists := source["dependency_completeness"]; exists {
		var ok bool
		complete, ok = raw.(bool)
		if !ok {
			return Action{}, fmt.Errorf("dependency_completeness must be boolean")
		}
	}
	validator, err := optionalText(source["validator_identity"], "validator_identity")
	if err != nil {
		return Action{}, err
	}
	raw := map[string]any{"schema_version": ActionSchema, "operation_identity": operationIdentity, "operation_version": operationVersion, "input_digest": inputDigest, "trust_scope": trustScope, "environment": environment, "dependencies": dependencyMaps(parsedDependencies), "side_effect_class": sideEffect, "authorization_scope_digest": pointerValue(authorizationDigest), "freshness": freshness, "dependency_completeness": complete, "validator_identity": pointerValue(validator)}
	digest, err := SHA256Canonical(raw)
	if err != nil {
		return Action{}, err
	}
	return Action{Raw: raw, Digest: digest, TrustScope: trustScope, AuthorizationScopeDigest: authorizationDigest, SideEffectClass: sideEffect, Dependencies: parsedDependencies, DependencyCompleteness: complete, ValidatorIdentity: validator}, nil
}

func ParseReceipt(source map[string]any, allowMissingDigest bool) (Receipt, error) {
	required := []string{"schema_version", "action", "action_digest", "result_digest", "media_type", "producer_identity", "reuse_class", "created_at", "dependency_snapshot", "trust_scope", "cache_scope"}
	if !allowMissingDigest {
		required = append(required, "receipt_digest")
	}
	if err := allowed(source, required, []string{"result_reference", "provenance", "revocation_ref", "validator_identity", "execution_metadata", "economics", "receipt_digest"}, "reuse receipt"); err != nil {
		return Receipt{}, err
	}
	schema, _, err := stringValue(source["schema_version"], "schema_version", false)
	if err != nil || schema != ReceiptSchema {
		return Receipt{}, fmt.Errorf("unsupported receipt schema")
	}
	actionSource, ok := source["action"].(map[string]any)
	if !ok {
		return Receipt{}, fmt.Errorf("receipt action must be an object")
	}
	action, err := ParseAction(actionSource)
	if err != nil {
		return Receipt{}, err
	}
	actionDigest, err := requiredDigest(source["action_digest"], "action_digest")
	if err != nil || actionDigest != action.Digest {
		return Receipt{}, fmt.Errorf("receipt action digest mismatch")
	}
	resultDigest, err := requiredDigest(source["result_digest"], "result_digest")
	if err != nil {
		return Receipt{}, err
	}
	reuseClass, _, err := stringValue(source["reuse_class"], "reuse_class", false)
	if err != nil || !map[string]bool{"EXACT": true, "VERIFIED": true, "ADVISORY": true, "UNSAFE": true}[reuseClass] {
		return Receipt{}, fmt.Errorf("unknown reuse class")
	}
	createdAt, _, err := stringValue(source["created_at"], "created_at", false)
	if err != nil {
		return Receipt{}, err
	}
	createdAt, err = CanonicalTimestamp(createdAt)
	if err != nil {
		return Receipt{}, err
	}
	snapshotArray, err := defaultArray(source["dependency_snapshot"])
	if err != nil {
		return Receipt{}, err
	}
	snapshot, err := parseDependencies(snapshotArray, "dependency_snapshot")
	if err != nil {
		return Receipt{}, err
	}
	mediaType, _, err := stringValue(source["media_type"], "media_type", false)
	if err != nil {
		return Receipt{}, err
	}
	producer, _, err := stringValue(source["producer_identity"], "producer_identity", false)
	if err != nil {
		return Receipt{}, err
	}
	trustScope, _, err := stringValue(source["trust_scope"], "trust_scope", false)
	if err != nil {
		return Receipt{}, err
	}
	cacheScope, _, err := stringValue(source["cache_scope"], "cache_scope", false)
	if err != nil {
		return Receipt{}, err
	}
	resultReference, err := optionalText(source["result_reference"], "result_reference")
	if err != nil {
		return Receipt{}, err
	}
	provenanceValue := any(map[string]any{})
	if raw, exists := source["provenance"]; exists {
		provenanceValue = raw
	}
	provenance, err := stringMap(provenanceValue, "provenance")
	if err != nil {
		return Receipt{}, err
	}
	revocation, err := optionalText(source["revocation_ref"], "revocation_ref")
	if err != nil {
		return Receipt{}, err
	}
	validator, err := optionalText(source["validator_identity"], "validator_identity")
	if err != nil {
		return Receipt{}, err
	}
	executionValue := any(map[string]any{})
	if raw, exists := source["execution_metadata"]; exists {
		executionValue = raw
	}
	execution, err := stringMap(executionValue, "execution_metadata")
	if err != nil {
		return Receipt{}, err
	}
	economicsValue := any(map[string]any{})
	if raw, exists := source["economics"]; exists {
		economicsValue = raw
	}
	economics, err := stringMap(economicsValue, "economics")
	if err != nil {
		return Receipt{}, err
	}
	raw := map[string]any{"schema_version": ReceiptSchema, "action": action.Raw, "action_digest": action.Digest, "result_digest": resultDigest, "result_reference": pointerValue(resultReference), "media_type": mediaType, "producer_identity": producer, "reuse_class": reuseClass, "created_at": createdAt, "dependency_snapshot": dependencyMaps(snapshot), "provenance": provenance, "trust_scope": trustScope, "cache_scope": cacheScope, "revocation_ref": pointerValue(revocation), "validator_identity": pointerValue(validator), "execution_metadata": execution, "economics": economics}
	receiptDigest, err := SHA256Canonical(raw)
	if err != nil {
		return Receipt{}, err
	}
	if !allowMissingDigest {
		supplied, err := requiredDigest(source["receipt_digest"], "receipt_digest")
		if err != nil || supplied != receiptDigest {
			return Receipt{}, fmt.Errorf("receipt digest mismatch")
		}
	}
	return Receipt{Raw: raw, Digest: receiptDigest, Action: action, ResultDigest: resultDigest, ReuseClass: reuseClass, TrustScope: trustScope, RevocationRef: revocation, ValidatorIdentity: validator, DependencySnapshot: snapshot, CacheScope: cacheScope, ProducerIdentity: producer, Provenance: provenance}, nil
}

func Evaluate(action Action, receipt Receipt, revoked bool, availableResultDigest string, validatorResult *bool, trustPolicy TrustPolicy) Decision {
	if revoked || receipt.RevocationRef != nil {
		return Decision{State: Revoked, Reason: "receipt revoked", ReceiptDigest: receipt.Digest}
	}
	if action.TrustScope != receipt.TrustScope || action.TrustScope != receipt.Action.TrustScope || pointerString(action.AuthorizationScopeDigest) != pointerString(receipt.Action.AuthorizationScopeDigest) {
		return Decision{State: ScopeMismatch, Reason: "scope mismatch", ReceiptDigest: receipt.Digest}
	}
	if action.SideEffectClass != "READ_ONLY" || receipt.Action.SideEffectClass != "READ_ONLY" {
		return Decision{State: Unsafe, Reason: "non-read-only action is not reusable", ReceiptDigest: receipt.Digest}
	}
	if receipt.ReuseClass == "UNSAFE" {
		return Decision{State: Unsafe, Reason: "receipt is marked unsafe", ReceiptDigest: receipt.Digest}
	}
	if !action.DependencyCompleteness || !receipt.Action.DependencyCompleteness {
		return Decision{State: Unknown, Reason: "dependency declaration is incomplete", ReceiptDigest: receipt.Digest}
	}
	if action.Digest != receipt.Action.Digest {
		return Decision{State: Stale, Reason: "action identity mismatch", ReceiptDigest: receipt.Digest}
	}
	left, _ := SHA256Canonical(dependencyMaps(action.Dependencies))
	right, _ := SHA256Canonical(dependencyMaps(receipt.DependencySnapshot))
	if left != right {
		return Decision{State: Stale, Reason: "dependency snapshot mismatch", ReceiptDigest: receipt.Digest}
	}
	if availableResultDigest != "" && (!digestPattern.MatchString(availableResultDigest) || availableResultDigest != receipt.ResultDigest) {
		return Decision{State: Unknown, Reason: "result digest mismatch", ReceiptDigest: receipt.Digest}
	}
	if receipt.ReuseClass == "EXACT" {
		if !admits(receipt, trustPolicy) {
			return Decision{State: Unknown, Reason: "receipt producer, cache scope, or provenance is not trusted", ReceiptDigest: receipt.Digest}
		}
		return Decision{State: ReusableExact, Reason: "identity and dependencies match", ReceiptDigest: receipt.Digest}
	}
	if receipt.ReuseClass == "VERIFIED" {
		if !admits(receipt, trustPolicy) {
			return Decision{State: Unknown, Reason: "receipt producer, cache scope, or provenance is not trusted", ReceiptDigest: receipt.Digest}
		}
		if receipt.ValidatorIdentity == nil || pointerString(receipt.ValidatorIdentity) != pointerString(action.ValidatorIdentity) {
			return Decision{State: RequiresValidation, Reason: "matching validator identity required", ReceiptDigest: receipt.Digest}
		}
		if validatorResult == nil {
			return Decision{State: RequiresValidation, Reason: "current validator required", ReceiptDigest: receipt.Digest}
		}
		if *validatorResult {
			return Decision{State: ReusableExact, Reason: "current validator passed", ReceiptDigest: receipt.Digest}
		}
		return Decision{State: Stale, Reason: "current validator rejected receipt", ReceiptDigest: receipt.Digest}
	}
	if receipt.ReuseClass == "ADVISORY" {
		return Decision{State: AdvisoryOnly, Reason: "context only; not authoritative", ReceiptDigest: receipt.Digest}
	}
	return Decision{State: Unsafe, Reason: "unknown reuse class", ReceiptDigest: receipt.Digest}
}

func defaultArray(value any) ([]any, error) {
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("expected array")
	}
	return array, nil
}

func dependencyMaps(value []map[string]any) []any {
	result := make([]any, len(value))
	for index, item := range value {
		result[index] = item
	}
	return result
}

func pointerValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func CloneObject(value map[string]any) (map[string]any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return decodeObject(encoded)
}

func MaterializeReceipt(base, patch map[string]any, recompute bool) (map[string]any, error) {
	result, err := CloneObject(base)
	if err != nil {
		return nil, err
	}
	for key, value := range patch {
		result[key] = value
	}
	if !recompute {
		return result, nil
	}
	delete(result, "receipt_digest")
	receipt, err := ParseReceipt(result, true)
	if err != nil {
		return nil, err
	}
	result["receipt_digest"] = receipt.Digest
	return result, nil
}
