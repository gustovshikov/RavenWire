package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"
)

// VectorConfigPath is the host-mounted path where sensor-agent writes Vector config.
const VectorConfigPath = "/etc/sensor/vector/vector.toml"

// defaultVectorHealthTimeout is the default timeout for polling Vector's health
// endpoint after a config reload.
const defaultVectorHealthTimeout = 15 * time.Second

// vectorHealthPollInterval is the interval between health endpoint polls.
const vectorHealthPollInterval = 500 * time.Millisecond

// vectorHealthURL is the default Vector internal health endpoint.
const vectorHealthURL = "http://127.0.0.1:8686/health"

// VectorConfigGenerator generates Vector TOML configuration from a SensorConfig bundle.
type VectorConfigGenerator struct {
	// ConfigPath is the path where the generated config is written.
	ConfigPath string
	// HealthTimeout is the timeout for polling Vector's health endpoint after reload.
	HealthTimeout time.Duration
	// HealthURL is the Vector internal health endpoint URL.
	HealthURL string
	// ValidateCmd is the command used to validate Vector config. Defaults to "vector".
	ValidateCmd string
	// SkipReload writes config without signaling or health-checking Vector.
	SkipReload bool
	// httpClient is used for health checks.
	httpClient *http.Client
	// signalVector sends SIGHUP to Vector. Overridable for testing.
	signalVector func() error
	// validateFunc overrides the default vector validate command. For testing.
	validateFunc func(content string) error
}

// NewVectorConfigGenerator creates a VectorConfigGenerator with defaults.
func NewVectorConfigGenerator() *VectorConfigGenerator {
	return &VectorConfigGenerator{
		ConfigPath:    VectorConfigPath,
		HealthTimeout: defaultVectorHealthTimeout,
		HealthURL:     vectorHealthURL,
		ValidateCmd:   "vector",
		httpClient:    &http.Client{Timeout: 5 * time.Second},
	}
}

// GenerateConfig renders the Vector TOML configuration from the given SensorConfig.
// It returns the rendered config as a string.
func (g *VectorConfigGenerator) GenerateConfig(cfg SensorConfig) (string, error) {
	funcMap := template.FuncMap{
		"vectorSinkType": vectorSinkType,
		"schemaVRL":      schemaTransformVRL,
		"deadLetterBytes": func(mb int) int64 {
			return int64(mb) * 1024 * 1024
		},
	}

	tmpl, err := template.New("vector.toml").Funcs(funcMap).Parse(vectorConfigTemplate)
	if err != nil {
		return "", fmt.Errorf("parse vector config template: %w", err)
	}

	data := vectorTemplateData{
		SeverityThreshold: cfg.SeverityThreshold,
		AlertListenerAddr: cfg.AlertListenerAddr,
		Sinks:             cfg.Sinks,
		DeadLetterPath:    cfg.DeadLetterPath,
		DeadLetterMaxMB:   cfg.DeadLetterMaxMB,
	}

	// Default alert listener address
	if data.AlertListenerAddr == "" {
		data.AlertListenerAddr = "http://127.0.0.1:9092"
	}

	// Default severity threshold
	if data.SeverityThreshold <= 0 {
		data.SeverityThreshold = 2
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute vector config template: %w", err)
	}

	return buf.String(), nil
}

// ValidateConfig runs `vector validate` on the given config content.
// Returns nil if valid, or an error with the validation output.
func (g *VectorConfigGenerator) ValidateConfig(configContent string) error {
	if g.validateFunc != nil {
		return g.validateFunc(configContent)
	}

	// Write config to a temp file for validation
	tmpFile, err := os.CreateTemp("", "vector-validate-*.toml")
	if err != nil {
		return fmt.Errorf("create temp file for vector validate: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp vector config: %w", err)
	}
	tmpFile.Close()

	cmdName := g.ValidateCmd
	if cmdName == "" {
		cmdName = "vector"
	}
	if _, err := exec.LookPath(cmdName); err != nil {
		log.Printf("config: %s not found; skipping external vector validate", cmdName)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdName, "validate", "--no-environment", tmpFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("vector validate failed: %w: %s", err, strings.TrimSpace(string(output)))
	}

	log.Printf("config: vector validate passed for generated config")
	return nil
}

// ApplyConfig generates, validates, writes, and reloads the Vector config.
// If the new config fails validation or Vector doesn't become healthy after reload,
// the previous config is restored.
func (g *VectorConfigGenerator) ApplyConfig(cfg SensorConfig) error {
	configContent, err := g.GenerateConfig(cfg)
	if err != nil {
		return fmt.Errorf("generate vector config: %w", err)
	}

	// Validate before writing
	if err := g.ValidateConfig(configContent); err != nil {
		return fmt.Errorf("vector config validation failed: %w", err)
	}

	configPath := g.ConfigPath
	if configPath == "" {
		configPath = VectorConfigPath
	}

	// Read previous config for rollback
	previousConfig, previousExists := readPreviousConfig(configPath)

	// Write the new config
	if err := writeConfigFile(configPath, configContent); err != nil {
		return fmt.Errorf("write vector config: %w", err)
	}
	if g.SkipReload {
		log.Printf("config: vector config written; reload skipped")
		return nil
	}

	// Signal Vector to reload
	if err := g.reloadVector(); err != nil {
		log.Printf("config: vector reload signal failed: %v", err)
		if previousExists {
			restorePreviousConfig(configPath, previousConfig)
		}
		return fmt.Errorf("signal vector reload: %w", err)
	}

	// Poll Vector health endpoint
	if err := g.waitForVectorHealthy(); err != nil {
		log.Printf("config: vector not healthy after reload: %v — restoring previous config", err)
		if previousExists {
			restorePreviousConfig(configPath, previousConfig)
			if reloadErr := g.reloadVector(); reloadErr != nil {
				log.Printf("config: failed to reload vector with restored config: %v", reloadErr)
			}
		}
		return fmt.Errorf("vector health check failed after reload: %w", err)
	}

	log.Printf("config: vector config applied and healthy")
	return nil
}

// reloadVector sends SIGHUP to Vector to trigger a config reload.
func (g *VectorConfigGenerator) reloadVector() error {
	if g.signalVector != nil {
		return g.signalVector()
	}
	return sendSignalByName("vector", 1) // SIGHUP = 1
}

// waitForVectorHealthy polls Vector's health endpoint until it returns 200
// or the timeout expires.
func (g *VectorConfigGenerator) waitForVectorHealthy() error {
	timeout := g.HealthTimeout
	if timeout <= 0 {
		timeout = defaultVectorHealthTimeout
	}

	healthURL := g.HealthURL
	if healthURL == "" {
		healthURL = vectorHealthURL
	}

	client := g.httpClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	deadline := time.Now().Add(timeout)
	var lastErr error

	for time.Now().Before(deadline) {
		resp, err := client.Get(healthURL)
		if err != nil {
			lastErr = err
			time.Sleep(vectorHealthPollInterval)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("vector health returned status %d", resp.StatusCode)
		time.Sleep(vectorHealthPollInterval)
	}

	return fmt.Errorf("vector did not become healthy within %s: %w", timeout, lastErr)
}

func readPreviousConfig(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func restorePreviousConfig(path, content string) {
	if err := writeConfigFile(path, content); err != nil {
		log.Printf("config: failed to restore previous vector config: %v", err)
	} else {
		log.Printf("config: restored previous vector config at %s", path)
	}
}

// vectorTemplateData holds the data passed to the Vector config template.
type vectorTemplateData struct {
	SeverityThreshold int
	AlertListenerAddr string
	Sinks             []SinkConfig
	DeadLetterPath    string
	DeadLetterMaxMB   int
}

// schemaTransformVRL returns the VRL transform source for the given schema mode.
func schemaTransformVRL(mode string) string {
	switch mode {
	case "ecs":
		return ecsTransformVRL
	case "ocsf":
		return ocsfTransformVRL
	case "splunk_cim":
		return splunkCIMTransformVRL
	default: // "raw" or unrecognized
		return rawTransformVRL
	}
}

// ParseSensorConfig parses a JSON sensor config bundle from the given content.
func ParseSensorConfig(content string) (SensorConfig, error) {
	var cfg SensorConfig
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return SensorConfig{}, fmt.Errorf("parse sensor config: %w", err)
	}
	return cfg, nil
}

// vectorSinkType maps our sink type names to Vector sink types.
func vectorSinkType(sinkType string) string {
	switch sinkType {
	case "splunk_hec":
		return "splunk_hec_logs"
	case "cribl_http":
		return "http"
	case "elasticsearch":
		return "elasticsearch"
	case "http":
		return "http"
	case "s3":
		return "aws_s3"
	case "kafka":
		return "kafka"
	default:
		return "http"
	}
}

// VRL transform snippets for each schema mode.
const rawTransformVRL = `  # raw mode: pass through unchanged`

const ecsTransformVRL = `  # ECS (Elastic Common Schema) transform
  .ecs = {}
  .ecs.version = "8.11"
  if exists(.src_ip) { .source = { "ip": .src_ip } }
  if exists(.dst_ip) { .destination = { "ip": .dst_ip } }
  if exists(.src_port) { .source.port = .src_port }
  if exists(.dst_port) { .destination.port = .dst_port }
  if exists(.proto) { .network = { "transport": downcase!(.proto) } }
  if exists(.community_id) { .network.community_id = .community_id }
  if exists(.alert) {
    .rule = {}
    if exists(.alert.signature) { .rule.name = .alert.signature }
    if exists(.alert.signature_id) { .rule.id = to_string!(.alert.signature_id) }
    if exists(.alert.severity) { .event = { "severity": .alert.severity } }
  }`

const ocsfTransformVRL = `  # OCSF (Open Cybersecurity Schema Framework) transform
  .ocsf = {}
  .ocsf.class_uid = 4001
  .ocsf.category_uid = 4
  .ocsf.activity_id = 1
  if exists(.src_ip) { .ocsf.src_endpoint = { "ip": .src_ip } }
  if exists(.dst_ip) { .ocsf.dst_endpoint = { "ip": .dst_ip } }
  if exists(.src_port) { .ocsf.src_endpoint.port = .src_port }
  if exists(.dst_port) { .ocsf.dst_endpoint.port = .dst_port }
  if exists(.community_id) { .ocsf.connection_info = { "community_id": .community_id } }
  if exists(.alert) {
    .ocsf.finding = {}
    if exists(.alert.signature) { .ocsf.finding.title = .alert.signature }
    if exists(.alert.severity) { .ocsf.severity_id = .alert.severity }
  }`

const splunkCIMTransformVRL = `  # Splunk CIM (Common Information Model) transform
  if exists(.src_ip) { .src = .src_ip }
  if exists(.dst_ip) { .dest = .dst_ip }
  if exists(.src_port) { .src_port = .src_port }
  if exists(.dst_port) { .dest_port = .dst_port }
  if exists(.proto) { .transport = downcase!(.proto) }
  if exists(.community_id) { .community_id = .community_id }
  if exists(.alert) {
    if exists(.alert.signature) { .signature = .alert.signature }
    if exists(.alert.signature_id) { .signature_id = to_string!(.alert.signature_id) }
    if exists(.alert.severity) { .severity = to_string!(.alert.severity) }
  }`

// vectorConfigTemplate is the Go text/template for generating Vector TOML config.
const vectorConfigTemplate = `# Vector configuration — generated by Sensor_Agent Config Applier
# DO NOT EDIT MANUALLY — this file is regenerated from the sensor config bundle.

[api]
enabled = true
address = "127.0.0.1:8686"

# ── Sources ──────────────────────────────────────────────────────────────────

[sources.zeek_logs]
type = "file"
include = ["/var/sensor/logs/zeek/*.log"]
read_from = "beginning"
ignore_older_secs = 86400

[sources.suricata_eve]
type = "file"
include = ["/var/sensor/logs/suricata/eve*.json"]
read_from = "beginning"
ignore_older_secs = 86400

# ── Transforms ───────────────────────────────────────────────────────────────

[transforms.parse_zeek]
type = "remap"
inputs = ["zeek_logs"]
source = '''
  . = parse_json!(string!(.message))
  .sensor_source = "zeek"
  .sensor_pod_id = get_env_var!("SENSOR_POD_NAME")
  if !exists(.community_id) {
    .community_id = null
  }
  if !exists(.ts) {
    .ts = now()
  }
'''

[transforms.parse_suricata]
type = "remap"
inputs = ["suricata_eve"]
source = '''
  . = parse_json!(string!(.message))
  .sensor_source = "suricata"
  .sensor_pod_id = get_env_var!("SENSOR_POD_NAME")
  if !exists(.community_id) {
    .community_id = null
  }
  if !exists(.timestamp) {
    .timestamp = now()
  }
'''

[transforms.normalize]
type = "remap"
inputs = ["parse_zeek", "parse_suricata"]
source = '''
  if exists(.community_id) && .community_id != null {
    .community_id = string!(.community_id)
  }
  .vector_ingest_ts = now()
'''

# Route qualifying Suricata alerts to the Alert_Listener.
# Severity threshold: {{ .SeverityThreshold }} (sourced from SensorConfig.SeverityThreshold)
[transforms.route_alerts]
type = "route"
inputs = ["parse_suricata"]

[transforms.route_alerts.route]
qualifying_alert = '.event_type == "alert" && exists(.alert.severity) && ((to_int(.alert.severity) ?? 999) <= {{ .SeverityThreshold }})'

# ── Alert_Listener sink ──────────────────────────────────────────────────────

[sinks.pcap_alert_webhook]
type = "http"
inputs = ["route_alerts.qualifying_alert"]
uri = "{{ .AlertListenerAddr }}/alerts"
method = "post"
encoding.codec = "json"

[sinks.pcap_alert_webhook.buffer]
type = "memory"
max_events = 1000
when_full = "drop_newest"
{{ range $i, $sink := .Sinks }}
# ── Sink: {{ $sink.Name }} ({{ $sink.Type }}) ────────────────────────────────
{{ if and $sink.SchemaMode (ne $sink.SchemaMode "raw") }}
[transforms.schema_{{ $sink.Name }}]
type = "remap"
inputs = ["normalize"]
source = '''
{{ schemaVRL $sink.SchemaMode }}
'''
{{ end }}
[sinks.{{ $sink.Name }}]
type = "{{ vectorSinkType $sink.Type }}"
inputs = [{{ if and $sink.SchemaMode (ne $sink.SchemaMode "raw") }}"schema_{{ $sink.Name }}"{{ else }}"normalize"{{ end }}]
{{ if eq $sink.Type "splunk_hec" -}}
endpoint = "{{ $sink.URI }}"
default_token = "{{ $sink.Token }}"
encoding.codec = "json"
{{ else if eq $sink.Type "elasticsearch" -}}
endpoints = ["{{ $sink.URI }}"]
encoding.codec = "json"
{{ else -}}
uri = "{{ $sink.URI }}"
method = "post"
encoding.codec = "json"
{{ if $sink.Token -}}
[sinks.{{ $sink.Name }}.auth]
strategy = "bearer"
token = "{{ $sink.Token }}"
{{ end -}}
{{ end }}
[sinks.{{ $sink.Name }}.buffer]
type = "disk"
max_size = 1073741824
when_full = "drop_newest"
{{ end }}{{ if .DeadLetterPath }}
# ── Dead-letter sink ─────────────────────────────────────────────────────────

[sinks.dead_letter]
type = "file"
inputs = ["normalize"]
path = "{{ .DeadLetterPath }}/dead-letter-%Y-%m-%d.json"
encoding.codec = "json"
{{ end }}`
