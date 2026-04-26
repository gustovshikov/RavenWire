package config

import (
	"encoding/json"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/sensor-stack/sensor-agent/internal/audit"
)

// Bundle is a configuration bundle sent from Config_Manager.
type Bundle struct {
	Type       string            `json:"type"`        // "pool_config", "suricata_rules", "zeek_policy", "vector_config", "bpf_filter"
	BundleB64  string            `json:"bundle_b64,omitempty"` // base64-encoded tar.gz for rule bundles
	Config     map[string]string `json:"config,omitempty"`     // key=path, value=content for config files
	Version    int               `json:"version"`
	UpdatedBy  string            `json:"updated_by"`
}

// Applier writes configuration files and signals services to reload.
type Applier struct {
	lastKnownPath string
	auditLog      *audit.Logger
	lastBundle    *Bundle
}

// NewApplier creates a new Config Applier.
func NewApplier(lastKnownPath string, auditLog *audit.Logger) *Applier {
	return &Applier{
		lastKnownPath: lastKnownPath,
		auditLog:      auditLog,
	}
}

// LoadLastKnown loads the last-known configuration from disk.
func (a *Applier) LoadLastKnown() error {
	data, err := os.ReadFile(a.lastKnownPath)
	if err != nil {
		return fmt.Errorf("read last-known config: %w", err)
	}

	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("parse last-known config: %w", err)
	}

	a.lastBundle = &bundle
	log.Printf("config: loaded last-known config (version=%d, updated_by=%s)", bundle.Version, bundle.UpdatedBy)
	return nil
}

// Apply writes the bundle's configuration files and signals services to reload.
// Returns validation errors if any; does not apply partial configs on error.
func (a *Applier) Apply(bundle Bundle, validator interface{ ValidateBundle(Bundle) []string }) []string {
	// Validate before writing anything
	if errs := validator.ValidateBundle(bundle); len(errs) > 0 {
		return errs
	}

	switch bundle.Type {
	case "suricata_rules":
		if err := a.applySuricataRules(bundle); err != nil {
			return []string{err.Error()}
		}
	case "zeek_policy":
		if err := a.applyZeekPolicy(bundle); err != nil {
			return []string{err.Error()}
		}
	case "vector_config":
		if err := a.applyVectorConfig(bundle); err != nil {
			return []string{err.Error()}
		}
	case "bpf_filter":
		if err := a.applyBPFFilter(bundle); err != nil {
			return []string{err.Error()}
		}
	case "pool_config":
		if err := a.applyPoolConfig(bundle); err != nil {
			return []string{err.Error()}
		}
	default:
		return []string{fmt.Sprintf("unknown bundle type %q", bundle.Type)}
	}

	// Persist last-known config
	a.lastBundle = &bundle
	if err := a.persistLastKnown(bundle); err != nil {
		log.Printf("config: failed to persist last-known config: %v", err)
	}

	a.auditLog.Log("apply-config", bundle.UpdatedBy, "success", map[string]any{
		"type":    bundle.Type,
		"version": bundle.Version,
	})

	return nil
}

func (a *Applier) applySuricataRules(bundle Bundle) error {
	rulesDir := "/etc/suricata/rules"

	// Support two payload formats:
	//   1. bundle_b64: base64-encoded tar.gz archive of rule files
	//   2. config map: filename → rule content (e.g. {"local.rules": "alert ..."})
	if bundle.BundleB64 != "" {
		if err := a.applySuricataRulesTarball(bundle.BundleB64, rulesDir); err != nil {
			return err
		}
	} else if len(bundle.Config) > 0 {
		if err := a.applySuricataRulesMap(bundle.Config, rulesDir); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("suricata_rules bundle requires bundle_b64 or config map")
	}

	// Signal Suricata to reload rules without container restart (Req 7.4)
	if err := sendSignalByName("suricata", syscall.SIGUSR2); err != nil {
		return fmt.Errorf("send SIGUSR2 to suricata: %w", err)
	}
	log.Printf("config: sent SIGUSR2 to suricata — rules reload triggered")
	return nil
}

// applySuricataRulesTarball extracts a base64-encoded tar.gz bundle atomically
// into rulesDir: extract to a temp dir, then rename into place.
func (a *Applier) applySuricataRulesTarball(bundleB64, rulesDir string) error {
	data, err := base64.StdEncoding.DecodeString(bundleB64)
	if err != nil {
		return fmt.Errorf("decode rules bundle: %w", err)
	}

	// Write tarball to a temp file
	tmpTar, err := os.CreateTemp("", "suricata-rules-*.tar.gz")
	if err != nil {
		return fmt.Errorf("create temp tarball: %w", err)
	}
	defer os.Remove(tmpTar.Name())

	if _, err := tmpTar.Write(data); err != nil {
		tmpTar.Close()
		return fmt.Errorf("write temp tarball: %w", err)
	}
	tmpTar.Close()

	// Extract to a staging directory (sibling of rulesDir for same-filesystem rename)
	stagingDir := rulesDir + ".staging"
	if err := os.RemoveAll(stagingDir); err != nil {
		return fmt.Errorf("clean staging dir: %w", err)
	}
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}

	cmd := exec.Command("tar", "-xzf", tmpTar.Name(), "-C", stagingDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(stagingDir)
		return fmt.Errorf("extract rules bundle: %w: %s", err, out)
	}

	// Atomically replace the rules directory
	oldDir := rulesDir + ".old"
	os.RemoveAll(oldDir)
	if err := os.MkdirAll(filepath.Dir(rulesDir), 0755); err != nil {
		os.RemoveAll(stagingDir)
		return fmt.Errorf("create parent dir: %w", err)
	}
	// Rename current → .old (best-effort; may not exist yet)
	_ = os.Rename(rulesDir, oldDir)
	if err := os.Rename(stagingDir, rulesDir); err != nil {
		// Attempt to restore
		_ = os.Rename(oldDir, rulesDir)
		return fmt.Errorf("atomic rename staging → rules dir: %w", err)
	}
	os.RemoveAll(oldDir)

	log.Printf("config: suricata rules extracted to %s (tarball)", rulesDir)
	return nil
}

// applySuricataRulesMap writes a map of filename → content atomically into rulesDir.
// Files are written to a staging directory first, then the directory is renamed.
func (a *Applier) applySuricataRulesMap(rulesMap map[string]string, rulesDir string) error {
	stagingDir := rulesDir + ".staging"
	if err := os.RemoveAll(stagingDir); err != nil {
		return fmt.Errorf("clean staging dir: %w", err)
	}
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}

	for filename, content := range rulesMap {
		// Sanitize: only allow the base filename, no path traversal
		safe := filepath.Base(filename)
		if safe == "." || safe == ".." || safe == "" {
			os.RemoveAll(stagingDir)
			return fmt.Errorf("invalid rule filename %q", filename)
		}
		dest := filepath.Join(stagingDir, safe)
		if err := os.WriteFile(dest, []byte(content), 0644); err != nil {
			os.RemoveAll(stagingDir)
			return fmt.Errorf("write rule file %s: %w", safe, err)
		}
		log.Printf("config: staged suricata rule file %s (%d bytes)", safe, len(content))
	}

	// Atomically replace the rules directory
	oldDir := rulesDir + ".old"
	os.RemoveAll(oldDir)
	if err := os.MkdirAll(filepath.Dir(rulesDir), 0755); err != nil {
		os.RemoveAll(stagingDir)
		return fmt.Errorf("create parent dir: %w", err)
	}
	_ = os.Rename(rulesDir, oldDir)
	if err := os.Rename(stagingDir, rulesDir); err != nil {
		_ = os.Rename(oldDir, rulesDir)
		return fmt.Errorf("atomic rename staging → rules dir: %w", err)
	}
	os.RemoveAll(oldDir)

	log.Printf("config: suricata rules written to %s (%d files)", rulesDir, len(rulesMap))
	return nil
}

func (a *Applier) applyZeekPolicy(bundle Bundle) error {
	for path, content := range bundle.Config {
		if err := writeConfigFile(path, content); err != nil {
			return err
		}
	}
	return sendSignalByName("zeek", syscall.SIGHUP)
}

func (a *Applier) applyVectorConfig(bundle Bundle) error {
	vectorConfig, ok := bundle.Config["/etc/vector/vector.toml"]
	if !ok {
		return fmt.Errorf("vector_config bundle missing /etc/vector/vector.toml")
	}
	if err := writeConfigFile("/etc/vector/vector.toml", vectorConfig); err != nil {
		return err
	}
	return sendSignalByName("vector", syscall.SIGHUP)
}

func (a *Applier) applyBPFFilter(bundle Bundle) error {
	filterContent, ok := bundle.Config["/etc/sensor/bpf_filters.conf"]
	if !ok {
		return fmt.Errorf("bpf_filter bundle missing /etc/sensor/bpf_filters.conf")
	}
	return writeConfigFile("/etc/sensor/bpf_filters.conf", filterContent)
}

func (a *Applier) applyPoolConfig(bundle Bundle) error {
	for path, content := range bundle.Config {
		if err := writeConfigFile(path, content); err != nil {
			return err
		}
	}
	return nil
}

func (a *Applier) persistLastKnown(bundle Bundle) error {
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.lastKnownPath, data, 0640)
}

func writeConfigFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create dir for %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	log.Printf("config: wrote %s", path)
	return nil
}

func sendSignalByName(name string, sig syscall.Signal) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		procName := string(comm)
		if len(procName) > 0 && procName[len(procName)-1] == '\n' {
			procName = procName[:len(procName)-1]
		}
		if procName == name {
			proc, err := os.FindProcess(pid)
			if err != nil {
				return err
			}
			return proc.Signal(sig)
		}
	}
	return fmt.Errorf("process %q not found", name)
}
