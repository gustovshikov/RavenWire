package rules

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/config"
)

// ValidationError describes a single rule validation failure.
type ValidationError struct {
	Rule    string `json:"rule,omitempty"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
}

func (e ValidationError) Error() string {
	if e.Rule != "" {
		return fmt.Sprintf("rule %s: %s", e.Rule, e.Message)
	}
	return e.Message
}

// Validator validates Suricata rules, BPF filters, and YARA rules.
type Validator struct {
	suricataConfigPath string
}

// NewValidator creates a new Validator.
func NewValidator() *Validator {
	return &Validator{
		suricataConfigPath: "/etc/suricata/suricata.yaml",
	}
}

// ValidateSuricata invokes `suricata -T` to validate a rules file or rules content.
// If rulesPath is a path to an existing file it is used directly; otherwise the
// content is written to a temporary file first.
// Returns structured errors for each invalid rule.
func (v *Validator) ValidateSuricata(rulesPath string) []ValidationError {
	path := rulesPath
	if _, err := os.Stat(rulesPath); err != nil {
		// rulesPath is raw content — write to a temp file
		tmp, err := os.CreateTemp("", "suricata-rules-*.rules")
		if err != nil {
			return []ValidationError{{Message: fmt.Sprintf("create temp rules file: %v", err)}}
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.WriteString(rulesPath); err != nil {
			tmp.Close()
			return []ValidationError{{Message: fmt.Sprintf("write temp rules file: %v", err)}}
		}
		tmp.Close()
		path = tmp.Name()
	}

	cmd := exec.Command("suricata", "-T",
		"-c", v.suricataConfigPath,
		"-S", path,
		"--disable-detection")

	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	return parseSuricataErrors(string(out))
}

// ValidateBPF validates a BPF filter expression by attempting a dry-run compile
// via SO_ATTACH_FILTER on a temporary AF_PACKET socket.
// Returns nil if the filter is valid or empty.
func (v *Validator) ValidateBPF(filter string) error {
	return compileBPFDryRun(filter)
}

// ValidateYARA invokes `yara --compile-rules` to validate YARA rule content.
// rulesContent may be a file path or raw rule text.
// Returns structured errors for each invalid rule.
func (v *Validator) ValidateYARA(rulesContent string) []ValidationError {
	path := rulesContent
	if _, err := os.Stat(rulesContent); err != nil {
		// rulesContent is raw text — write to a temp file
		tmp, err := os.CreateTemp("", "yara-rules-*.yar")
		if err != nil {
			return []ValidationError{{Message: fmt.Sprintf("create temp YARA file: %v", err)}}
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.WriteString(rulesContent); err != nil {
			tmp.Close()
			return []ValidationError{{Message: fmt.Sprintf("write temp YARA file: %v", err)}}
		}
		tmp.Close()
		path = tmp.Name()
	}

	// yarac compiles rules to a binary; --compile-rules is the yarac flag.
	// We compile to /dev/null so no output file is written.
	cmd := exec.Command("yarac", path, "/dev/null")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	return parseYARAErrors(string(out))
}

// ValidateBundle validates a config bundle before applying it.
// Returns a slice of error strings (empty = valid).
func (v *Validator) ValidateBundle(bundle config.Bundle) []string {
	var errs []string

	switch bundle.Type {
	case "suricata_rules":
		if bundle.BundleB64 == "" && len(bundle.Config) == 0 {
			errs = append(errs, "suricata_rules bundle requires bundle_b64 or config map")
		} else if len(bundle.Config) > 0 {
			// Deep syntax validation for config-map payloads: validate each file's content.
			for filename, content := range bundle.Config {
				if validationErrs := v.ValidateSuricata(content); len(validationErrs) > 0 {
					for _, ve := range validationErrs {
						errs = append(errs, fmt.Sprintf("%s: %s", filename, ve.Message))
					}
				}
			}
		}
		// BundleB64 (tarball) path: skip deep syntax validation — contents can't be
		// easily validated without extraction. Non-empty check already done above.
	case "bpf_filter":
		if filter, ok := bundle.Config["/etc/sensor/bpf_filters.conf"]; ok {
			if err := v.ValidateBPF(filter); err != nil {
				errs = append(errs, fmt.Sprintf("BPF filter validation failed: %v", err))
			}
		}
	case "vector_config", "zeek_policy", "pool_config":
		// No pre-apply validation for these types in MVP
	default:
		errs = append(errs, fmt.Sprintf("unknown bundle type %q", bundle.Type))
	}

	return errs
}

// parseSuricataErrors parses suricata -T output and returns structured errors.
func parseSuricataErrors(output string) []ValidationError {
	var errs []ValidationError
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "Error") || strings.Contains(line, "error") ||
			strings.Contains(line, "Failed") || strings.Contains(line, "failed") {
			errs = append(errs, ValidationError{Message: line})
		}
	}
	if len(errs) == 0 && output != "" {
		errs = append(errs, ValidationError{Message: "suricata -T failed: " + output})
	}
	return errs
}

// parseYARAErrors parses yarac output and returns structured errors.
// yarac error lines look like: "error: <file>(<line>): <message>"
func parseYARAErrors(output string) []ValidationError {
	var errs []ValidationError
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "error:") || strings.HasPrefix(line, "warning:") {
			// Strip the "error: " prefix for a cleaner message
			msg := strings.TrimPrefix(line, "error: ")
			msg = strings.TrimPrefix(msg, "warning: ")
			errs = append(errs, ValidationError{Message: msg})
		}
	}
	if len(errs) == 0 && output != "" {
		errs = append(errs, ValidationError{Message: "yarac failed: " + output})
	}
	return errs
}
