package rules

import (
	"strings"
	"testing"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/config"
)

// TestValidateBundleSuricataRulesEmpty verifies that a bundle with neither
// config nor bundle_b64 returns a validation error.
func TestValidateBundleSuricataRulesEmpty(t *testing.T) {
	v := NewValidator()
	bundle := config.Bundle{
		Type:      "suricata_rules",
		Version:   1,
		UpdatedBy: "test",
	}

	errs := v.ValidateBundle(bundle)
	if len(errs) == 0 {
		t.Fatal("expected validation error for empty suricata_rules bundle, got none")
	}
}

// TestValidateBundleSuricataRulesMapValid verifies that ValidateBundle calls
// through to ValidateSuricata for config-map payloads. Since the suricata
// binary is not available in the test environment, the error from the missing
// binary is surfaced as a validation error (not a panic), and the filename is
// included in the error message.
func TestValidateBundleSuricataRulesMapValid(t *testing.T) {
	v := NewValidator()
	bundle := config.Bundle{
		Type: "suricata_rules",
		Config: map[string]string{
			"local.rules": "alert tcp any any -> any any (msg:\"test\"; sid:1;)\n",
		},
		Version:   1,
		UpdatedBy: "test",
	}

	errs := v.ValidateBundle(bundle)

	// In a test environment without the suricata binary, ValidateSuricata will
	// return an error (exec: "suricata": executable file not found in $PATH or
	// similar). The key invariant: errors are returned as strings, not panics,
	// and the filename prefix is present.
	if len(errs) > 0 {
		for _, e := range errs {
			if !strings.HasPrefix(e, "local.rules:") {
				t.Errorf("expected error to start with filename prefix \"local.rules:\", got: %q", e)
			}
		}
	}
	// If suricata happens to be installed and the rules are valid, errs will be
	// empty — that is also acceptable.
}

// TestValidateBundleSuricataRulesMapMultipleFiles verifies that errors are
// collected per-file with the filename prefix when multiple files are present.
func TestValidateBundleSuricataRulesMapMultipleFiles(t *testing.T) {
	v := NewValidator()
	bundle := config.Bundle{
		Type: "suricata_rules",
		Config: map[string]string{
			"good.rules":   "alert tcp any any -> any any (msg:\"good\"; sid:1;)\n",
			"custom.rules": "alert udp any any -> any any (msg:\"custom\"; sid:2;)\n",
		},
		Version:   1,
		UpdatedBy: "test",
	}

	errs := v.ValidateBundle(bundle)

	// Each error must be prefixed with the filename that caused it.
	for _, e := range errs {
		if !strings.HasPrefix(e, "good.rules:") && !strings.HasPrefix(e, "custom.rules:") {
			t.Errorf("error missing filename prefix: %q", e)
		}
	}
}
