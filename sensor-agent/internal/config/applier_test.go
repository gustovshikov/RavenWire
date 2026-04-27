package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
)

func newTestApplier(t *testing.T) (*Applier, string) {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	auditLog, err := audit.New(auditPath)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })
	lastKnown := filepath.Join(dir, "last-known.json")
	return NewApplier(lastKnown, auditLog), dir
}

// noopValidator satisfies the validator interface without invoking suricata.
type noopValidator struct{}

func (noopValidator) ValidateBundle(_ Bundle) []string { return nil }

// TestApplySuricataRulesMap verifies that a config-map bundle writes rule files
// atomically to the target directory and that the staging dir is cleaned up.
func TestApplySuricataRulesMap(t *testing.T) {
	applier, tmpDir := newTestApplier(t)

	rulesDir := filepath.Join(tmpDir, "suricata", "rules")

	// Patch the rules dir path by calling the internal helper directly.
	rules := map[string]string{
		"local.rules":  "alert tcp any any -> any any (msg:\"test\"; sid:1;)\n",
		"custom.rules": "alert udp any any -> any any (msg:\"udp\"; sid:2;)\n",
	}

	if err := applier.applySuricataRulesMap(rules, rulesDir); err != nil {
		t.Fatalf("applySuricataRulesMap: %v", err)
	}

	// Verify files were written
	for filename, content := range rules {
		path := filepath.Join(rulesDir, filename)
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("rule file %s not found: %v", filename, err)
			continue
		}
		if string(got) != content {
			t.Errorf("rule file %s: got %q, want %q", filename, got, content)
		}
	}

	// Staging dir must be cleaned up
	stagingDir := rulesDir + ".staging"
	if _, err := os.Stat(stagingDir); !os.IsNotExist(err) {
		t.Errorf("staging dir %s should have been removed", stagingDir)
	}
}

// TestApplySuricataRulesMapIdempotent verifies that applying a second bundle
// replaces the first (atomic overwrite).
func TestApplySuricataRulesMapIdempotent(t *testing.T) {
	applier, tmpDir := newTestApplier(t)
	rulesDir := filepath.Join(tmpDir, "suricata", "rules")

	first := map[string]string{"v1.rules": "alert tcp any any -> any any (msg:\"v1\"; sid:10;)\n"}
	second := map[string]string{"v2.rules": "alert tcp any any -> any any (msg:\"v2\"; sid:20;)\n"}

	if err := applier.applySuricataRulesMap(first, rulesDir); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := applier.applySuricataRulesMap(second, rulesDir); err != nil {
		t.Fatalf("second apply: %v", err)
	}

	// v1.rules must be gone (replaced, not merged)
	if _, err := os.Stat(filepath.Join(rulesDir, "v1.rules")); !os.IsNotExist(err) {
		t.Error("v1.rules should have been replaced by second bundle")
	}
	// v2.rules must exist
	if _, err := os.Stat(filepath.Join(rulesDir, "v2.rules")); err != nil {
		t.Errorf("v2.rules should exist after second bundle: %v", err)
	}
}

// TestApplySuricataRulesMapPathTraversal verifies that filenames with path
// separators are sanitized to their base name only, preventing directory traversal.
func TestApplySuricataRulesMapPathTraversal(t *testing.T) {
	applier, tmpDir := newTestApplier(t)
	rulesDir := filepath.Join(tmpDir, "suricata", "rules")

	// Attempt path traversal via filename — filepath.Base strips the leading "../"
	// so the file lands as "evil.rules" inside the rules dir, not outside it.
	rules := map[string]string{
		"../evil.rules": "alert tcp any any -> any any (msg:\"evil\"; sid:99;)\n",
	}

	if err := applier.applySuricataRulesMap(rules, rulesDir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The file must be inside rulesDir, not in the parent directory
	escapedPath := filepath.Join(tmpDir, "evil.rules")
	if _, err := os.Stat(escapedPath); !os.IsNotExist(err) {
		t.Error("path traversal succeeded: evil.rules was written outside the rules dir")
	}

	// The sanitized file should exist inside rulesDir
	safePath := filepath.Join(rulesDir, "evil.rules")
	if _, err := os.Stat(safePath); err != nil {
		t.Errorf("sanitized file should exist inside rules dir: %v", err)
	}
}

// TestApplyBundleValidationError verifies that Apply returns errors without
// writing anything when the validator rejects the bundle.
func TestApplyBundleValidationError(t *testing.T) {
	applier, tmpDir := newTestApplier(t)
	rulesDir := filepath.Join(tmpDir, "suricata", "rules")

	rejectValidator := rejectAll{}
	bundle := Bundle{
		Type:      "suricata_rules",
		Config:    map[string]string{"local.rules": "alert tcp any any -> any any (msg:\"x\"; sid:1;)\n"},
		Version:   1,
		UpdatedBy: "test",
	}

	errs := applier.Apply(bundle, rejectValidator)
	if len(errs) == 0 {
		t.Error("expected validation errors, got none")
	}

	// Rules dir must not have been created
	if _, err := os.Stat(rulesDir); !os.IsNotExist(err) {
		t.Error("rules dir should not exist after validation failure")
	}
}

type rejectAll struct{}

func (rejectAll) ValidateBundle(_ Bundle) []string { return []string{"rejected by test"} }
