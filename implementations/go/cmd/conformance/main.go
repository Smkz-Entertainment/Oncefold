package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Smkz-Entertainment/Oncefold/implementations/go/verifier"
)

type vectorDocument struct {
	Canonicalization struct {
		UTF8KeyOrder       map[string]any `json:"utf8_key_order"`
		UTF8KeyOrderDigest string         `json:"utf8_key_order_digest"`
	} `json:"canonicalization"`
	Base struct {
		Action  map[string]any `json:"action"`
		Receipt map[string]any `json:"receipt"`
	} `json:"base"`
	Cases        []vectorCase         `json:"cases"`
	TrustPolicy  verifier.TrustPolicy `json:"trust_policy"`
	RawJSONCases []rawJSONCase        `json:"raw_json_cases"`
	Timestamps   []timestampCase      `json:"timestamp_cases"`
}

type vectorCase struct {
	ID                    string         `json:"id"`
	ActionPatch           map[string]any `json:"action_patch"`
	ReceiptPatch          map[string]any `json:"receipt_patch"`
	RecomputeReceipt      bool           `json:"recompute_receipt_digest"`
	Revoked               bool           `json:"revoked"`
	AvailableResultDigest string         `json:"available_result_digest"`
	ValidatorResult       *bool          `json:"validator_result"`
	ExpectedState         string         `json:"expected_state"`
}

type rawJSONCase struct {
	ID       string `json:"id"`
	JSON     string `json:"json"`
	Accepted bool   `json:"accepted"`
}

type timestampCase struct {
	Value     string `json:"value"`
	Accepted  bool   `json:"accepted"`
	Canonical string `json:"canonical"`
}

func merge(base, patch map[string]any) (map[string]any, error) {
	result, err := verifier.CloneObject(base)
	if err != nil {
		return nil, err
	}
	for key, value := range patch {
		result[key] = value
	}
	return result, nil
}

func main() {
	vectorPath := "conformance/vectors.json"
	if len(os.Args) > 1 {
		vectorPath = os.Args[1]
	} else if _, err := os.Stat(vectorPath); err != nil {
		vectorPath = filepath.Join("..", "..", "conformance", "vectors.json")
	}
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		panic(err)
	}
	value, err := verifier.ParseJSON(data)
	if err != nil {
		panic(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var document vectorDocument
	if err := json.Unmarshal(encoded, &document); err != nil {
		panic(err)
	}
	failures := []string{}
	keyOrderDigest, digestErr := verifier.SHA256Canonical(document.Canonicalization.UTF8KeyOrder)
	if digestErr != nil || keyOrderDigest != document.Canonicalization.UTF8KeyOrderDigest {
		failures = append(failures, "canonicalization: UTF-8 key order digest mismatch")
	}
	for _, item := range document.Timestamps {
		actual, timestampErr := verifier.CanonicalTimestamp(item.Value)
		if timestampErr != nil {
			if item.Accepted {
				failures = append(failures, fmt.Sprintf("timestamp rejected %s", item.Value))
			}
			continue
		}
		if !item.Accepted || (item.Canonical != "" && actual != item.Canonical) {
			failures = append(failures, fmt.Sprintf("timestamp %s", item.Value))
		}
	}
	for _, item := range document.RawJSONCases {
		_, parseErr := verifier.ParseJSON([]byte(item.JSON))
		accepted := parseErr == nil
		if accepted != item.Accepted {
			failures = append(failures, fmt.Sprintf("raw JSON %s", item.ID))
		}
	}
	for _, item := range document.Cases {
		actual := verifier.Unknown
		actionPayload, actionErr := merge(document.Base.Action, item.ActionPatch)
		receiptPayload, receiptErr := verifier.MaterializeReceipt(document.Base.Receipt, item.ReceiptPatch, item.RecomputeReceipt)
		if actionErr == nil && receiptErr == nil {
			action, parseActionErr := verifier.ParseAction(actionPayload)
			receipt, parseReceiptErr := verifier.ParseReceipt(receiptPayload, false)
			if parseActionErr == nil && parseReceiptErr == nil {
				actual = verifier.Evaluate(action, receipt, item.Revoked, item.AvailableResultDigest, item.ValidatorResult, document.TrustPolicy).State
			}
		}
		if actual != item.ExpectedState {
			failures = append(failures, fmt.Sprintf("%s: expected %s, got %s", item.ID, item.ExpectedState, actual))
		}
	}
	output := map[string]any{"implementation": "go-independent", "total": len(document.Cases), "passed": len(document.Cases) - len(failures), "failures": failures}
	encoded, _ = json.MarshalIndent(output, "", "  ")
	fmt.Println(string(encoded))
	if len(failures) > 0 {
		os.Exit(1)
	}
}
