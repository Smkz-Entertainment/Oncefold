package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Smkz-Entertainment/Oncefold/implementations/go/verifier"
)

type vectorDocument struct {
	Base struct {
		Action  map[string]any `json:"action"`
		Receipt map[string]any `json:"receipt"`
	} `json:"base"`
	Cases []vectorCase `json:"cases"`
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
	var document vectorDocument
	if err := json.Unmarshal(data, &document); err != nil {
		panic(err)
	}
	failures := []string{}
	for _, item := range document.Cases {
		actual := verifier.Unknown
		actionPayload, actionErr := merge(document.Base.Action, item.ActionPatch)
		receiptPayload, receiptErr := verifier.MaterializeReceipt(document.Base.Receipt, item.ReceiptPatch, item.RecomputeReceipt)
		if actionErr == nil && receiptErr == nil {
			action, parseActionErr := verifier.ParseAction(actionPayload)
			receipt, parseReceiptErr := verifier.ParseReceipt(receiptPayload, false)
			if parseActionErr == nil && parseReceiptErr == nil {
				actual = verifier.Evaluate(action, receipt, item.Revoked, item.AvailableResultDigest, item.ValidatorResult).State
			}
		}
		if actual != item.ExpectedState {
			failures = append(failures, fmt.Sprintf("%s: expected %s, got %s", item.ID, item.ExpectedState, actual))
		}
	}
	output := map[string]any{"implementation": "go-independent", "total": len(document.Cases), "passed": len(document.Cases) - len(failures), "failures": failures}
	encoded, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(encoded))
	if len(failures) > 0 {
		os.Exit(1)
	}
}
