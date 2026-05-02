package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
)

// TestGenerateConfigBasicSources verifies that the generated config always
// includes the Zeek and Suricata sources and the core transforms.
func TestGenerateConfigBasicSources(t *testing.T) {
	gen := NewVectorConfigGenerator()
	cfg := SensorConfig{
		SeverityThreshold: 2,
	}

	content, err := gen.GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	required := []string{
		"[sources.zeek_logs]",
		"[sources.suricata_eve]",
		"[transforms.parse_zeek]",
		"[transforms.parse_suricata]",
		"[transforms.normalize]",
		"[transforms.route_alerts]",
		"[sinks.pcap_alert_webhook]",
	}

	for _, s := range required {
		if !strings.Contains(content, s) {
			t.Errorf("generated config missing required section %q", s)
		}
	}
}

// TestGenerateConfigSeverityThreshold verifies the severity threshold in the
// alert routing rule matches the configured value.
func TestGenerateConfigSeverityThreshold(t *testing.T) {
	gen := NewVectorConfigGenerator()

	for _, threshold := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("threshold_%d", threshold), func(t *testing.T) {
			cfg := SensorConfig{SeverityThreshold: threshold}
			content, err := gen.GenerateConfig(cfg)
			if err != nil {
				t.Fatalf("GenerateConfig: %v", err)
			}

			expected := fmt.Sprintf("<= %d)", threshold)
			if !strings.Contains(content, expected) {
				t.Errorf("generated config should contain severity threshold %d in route rule", threshold)
			}
		})
	}
}

// TestGenerateConfigDefaultSeverityThreshold verifies that a zero threshold
// defaults to 2.
func TestGenerateConfigDefaultSeverityThreshold(t *testing.T) {
	gen := NewVectorConfigGenerator()
	cfg := SensorConfig{SeverityThreshold: 0}

	content, err := gen.GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	if !strings.Contains(content, "<= 2)") {
		t.Error("zero severity threshold should default to 2")
	}
}

// TestGenerateConfigSinkIsolation verifies that only configured sinks appear
// in the generated config (Requirement 8.2).
func TestGenerateConfigSinkIsolation(t *testing.T) {
	gen := NewVectorConfigGenerator()

	tests := []struct {
		name          string
		sinks         []SinkConfig
		wantSinks     []string
		dontWantSinks []string
	}{
		{
			name:          "no sinks",
			sinks:         nil,
			wantSinks:     []string{"pcap_alert_webhook"}, // always present
			dontWantSinks: []string{"splunk", "cribl", "elasticsearch"},
		},
		{
			name: "only elasticsearch",
			sinks: []SinkConfig{
				{Name: "es_main", Type: "elasticsearch", URI: "https://es.example.com:9200", SchemaMode: "ecs"},
			},
			wantSinks:     []string{"pcap_alert_webhook", "es_main"},
			dontWantSinks: []string{"splunk", "cribl"},
		},
		{
			name: "splunk and cribl",
			sinks: []SinkConfig{
				{Name: "splunk_prod", Type: "splunk_hec", URI: "https://splunk.example.com:8088", SchemaMode: "splunk_cim", Token: "abc123"},
				{Name: "cribl_stream", Type: "cribl_http", URI: "https://cribl.example.com/api", SchemaMode: "raw", Token: "xyz789"},
			},
			wantSinks:     []string{"pcap_alert_webhook", "splunk_prod", "cribl_stream"},
			dontWantSinks: []string{"elasticsearch"},
		},
		{
			name: "all three",
			sinks: []SinkConfig{
				{Name: "splunk_prod", Type: "splunk_hec", URI: "https://splunk.example.com:8088", SchemaMode: "raw", Token: "abc"},
				{Name: "cribl_stream", Type: "cribl_http", URI: "https://cribl.example.com/api", SchemaMode: "raw"},
				{Name: "es_main", Type: "elasticsearch", URI: "https://es.example.com:9200", SchemaMode: "ecs"},
			},
			wantSinks:     []string{"pcap_alert_webhook", "splunk_prod", "cribl_stream", "es_main"},
			dontWantSinks: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := SensorConfig{
				SeverityThreshold: 2,
				Sinks:             tt.sinks,
			}

			content, err := gen.GenerateConfig(cfg)
			if err != nil {
				t.Fatalf("GenerateConfig: %v", err)
			}

			for _, sink := range tt.wantSinks {
				sinkHeader := fmt.Sprintf("[sinks.%s]", sink)
				if !strings.Contains(content, sinkHeader) {
					t.Errorf("generated config should contain sink %q", sink)
				}
			}

			for _, sink := range tt.dontWantSinks {
				sinkHeader := fmt.Sprintf("[sinks.%s]", sink)
				if strings.Contains(content, sinkHeader) {
					t.Errorf("generated config should NOT contain sink %q", sink)
				}
			}
		})
	}
}

// TestGenerateConfigSplunkHECSink verifies Splunk HEC sink uses the correct
// Vector sink type and includes the token.
func TestGenerateConfigSplunkHECSink(t *testing.T) {
	gen := NewVectorConfigGenerator()
	cfg := SensorConfig{
		SeverityThreshold: 2,
		Sinks: []SinkConfig{
			{Name: "splunk_prod", Type: "splunk_hec", URI: "https://splunk.example.com:8088", SchemaMode: "raw", Token: "my-token"},
		},
	}

	content, err := gen.GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	if !strings.Contains(content, `type = "splunk_hec_logs"`) {
		t.Error("splunk_hec sink should use Vector type splunk_hec_logs")
	}
	if !strings.Contains(content, `default_token = "my-token"`) {
		t.Error("splunk_hec sink should include the token")
	}
	if !strings.Contains(content, `endpoint = "https://splunk.example.com:8088"`) {
		t.Error("splunk_hec sink should include the endpoint URI")
	}
}

// TestGenerateConfigElasticsearchSink verifies Elasticsearch sink uses the
// correct Vector sink type.
func TestGenerateConfigElasticsearchSink(t *testing.T) {
	gen := NewVectorConfigGenerator()
	cfg := SensorConfig{
		SeverityThreshold: 2,
		Sinks: []SinkConfig{
			{Name: "es_main", Type: "elasticsearch", URI: "https://es.example.com:9200", SchemaMode: "raw"},
		},
	}

	content, err := gen.GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	if !strings.Contains(content, `type = "elasticsearch"`) {
		t.Error("elasticsearch sink should use Vector type elasticsearch")
	}
	if !strings.Contains(content, `endpoints = ["https://es.example.com:9200"]`) {
		t.Error("elasticsearch sink should include the endpoints array")
	}
}

// TestGenerateConfigHTTPSinkWithToken verifies HTTP sinks include bearer auth
// when a token is provided.
func TestGenerateConfigHTTPSinkWithToken(t *testing.T) {
	gen := NewVectorConfigGenerator()
	cfg := SensorConfig{
		SeverityThreshold: 2,
		Sinks: []SinkConfig{
			{Name: "cribl_stream", Type: "cribl_http", URI: "https://cribl.example.com/api", SchemaMode: "raw", Token: "bearer-tok"},
		},
	}

	content, err := gen.GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	if !strings.Contains(content, `strategy = "bearer"`) {
		t.Error("HTTP sink with token should include bearer auth strategy")
	}
	if !strings.Contains(content, `token = "bearer-tok"`) {
		t.Error("HTTP sink with token should include the token value")
	}
}

// TestGenerateConfigSchemaTransforms verifies that per-sink schema transforms
// are generated for non-raw modes.
func TestGenerateConfigSchemaTransforms(t *testing.T) {
	gen := NewVectorConfigGenerator()

	tests := []struct {
		mode       string
		wantTransform bool
		wantSnippet   string
	}{
		{"raw", false, ""},
		{"ecs", true, "ECS (Elastic Common Schema)"},
		{"ocsf", true, "OCSF (Open Cybersecurity Schema Framework)"},
		{"splunk_cim", true, "Splunk CIM (Common Information Model)"},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			cfg := SensorConfig{
				SeverityThreshold: 2,
				Sinks: []SinkConfig{
					{Name: "test_sink", Type: "http", URI: "https://example.com", SchemaMode: tt.mode},
				},
			}

			content, err := gen.GenerateConfig(cfg)
			if err != nil {
				t.Fatalf("GenerateConfig: %v", err)
			}

			transformHeader := "[transforms.schema_test_sink]"
			hasTransform := strings.Contains(content, transformHeader)

			if tt.wantTransform && !hasTransform {
				t.Errorf("schema mode %q should generate a transform", tt.mode)
			}
			if !tt.wantTransform && hasTransform {
				t.Errorf("schema mode %q should NOT generate a transform", tt.mode)
			}

			if tt.wantTransform {
				// The sink should reference the schema transform as input
				if !strings.Contains(content, fmt.Sprintf(`"schema_test_sink"`)) {
					t.Errorf("sink with schema mode %q should reference schema transform as input", tt.mode)
				}
			}

			if tt.wantSnippet != "" && !strings.Contains(content, tt.wantSnippet) {
				t.Errorf("schema mode %q should contain snippet %q", tt.mode, tt.wantSnippet)
			}
		})
	}
}

// TestGenerateConfigDeadLetterSink verifies the dead-letter sink is included
// only when configured (Requirement 8.5).
func TestGenerateConfigDeadLetterSink(t *testing.T) {
	gen := NewVectorConfigGenerator()

	t.Run("no dead letter", func(t *testing.T) {
		cfg := SensorConfig{SeverityThreshold: 2}
		content, err := gen.GenerateConfig(cfg)
		if err != nil {
			t.Fatalf("GenerateConfig: %v", err)
		}
		if strings.Contains(content, "[sinks.dead_letter]") {
			t.Error("dead-letter sink should not appear when not configured")
		}
	})

	t.Run("with dead letter", func(t *testing.T) {
		cfg := SensorConfig{
			SeverityThreshold: 2,
			DeadLetterPath:    "/var/sensor/dead-letter",
			DeadLetterMaxMB:   512,
		}
		content, err := gen.GenerateConfig(cfg)
		if err != nil {
			t.Fatalf("GenerateConfig: %v", err)
		}
		if !strings.Contains(content, "[sinks.dead_letter]") {
			t.Error("dead-letter sink should appear when configured")
		}
		if !strings.Contains(content, "/var/sensor/dead-letter") {
			t.Error("dead-letter sink should use the configured path")
		}
	})
}

// TestGenerateConfigAlertListenerAddr verifies the alert listener address
// is used in the webhook sink URI.
func TestGenerateConfigAlertListenerAddr(t *testing.T) {
	gen := NewVectorConfigGenerator()

	t.Run("custom address", func(t *testing.T) {
		cfg := SensorConfig{
			SeverityThreshold: 2,
			AlertListenerAddr: "http://10.0.0.1:9092",
		}
		content, err := gen.GenerateConfig(cfg)
		if err != nil {
			t.Fatalf("GenerateConfig: %v", err)
		}
		if !strings.Contains(content, `uri = "http://10.0.0.1:9092/alerts"`) {
			t.Error("webhook sink should use the configured alert listener address")
		}
	})

	t.Run("default address", func(t *testing.T) {
		cfg := SensorConfig{SeverityThreshold: 2}
		content, err := gen.GenerateConfig(cfg)
		if err != nil {
			t.Fatalf("GenerateConfig: %v", err)
		}
		if !strings.Contains(content, `uri = "http://127.0.0.1:9092/alerts"`) {
			t.Error("webhook sink should default to localhost:9092")
		}
	})
}

// TestValidateConfigSuccess verifies that ValidateConfig succeeds when the
// validate function returns nil.
func TestValidateConfigSuccess(t *testing.T) {
	gen := NewVectorConfigGenerator()
	gen.validateFunc = func(content string) error { return nil }

	err := gen.ValidateConfig("valid config content")
	if err != nil {
		t.Fatalf("ValidateConfig should succeed: %v", err)
	}
}

// TestValidateConfigFailure verifies that ValidateConfig returns an error
// when the validate function fails.
func TestValidateConfigFailure(t *testing.T) {
	gen := NewVectorConfigGenerator()
	gen.validateFunc = func(content string) error {
		return fmt.Errorf("invalid TOML at line 42")
	}

	err := gen.ValidateConfig("bad config")
	if err == nil {
		t.Fatal("ValidateConfig should fail")
	}
	if !strings.Contains(err.Error(), "invalid TOML") {
		t.Errorf("error should contain validation message, got: %v", err)
	}
}

// TestApplyConfigValidationRejectsBundle verifies that ApplyConfig does not
// write the config file when validation fails (Requirement 8.4).
func TestApplyConfigValidationRejectsBundle(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "vector.toml")

	gen := NewVectorConfigGenerator()
	gen.ConfigPath = configPath
	gen.validateFunc = func(content string) error {
		return fmt.Errorf("validation failed")
	}

	cfg := SensorConfig{SeverityThreshold: 2}
	err := gen.ApplyConfig(cfg)
	if err == nil {
		t.Fatal("ApplyConfig should fail when validation fails")
	}

	// Config file should not have been written
	if _, statErr := os.Stat(configPath); !os.IsNotExist(statErr) {
		t.Error("config file should not exist after validation failure")
	}
}

// TestApplyConfigHealthCheckRestoresPrevious verifies that when Vector doesn't
// become healthy after reload, the previous config is restored (Requirement 8.7).
func TestApplyConfigHealthCheckRestoresPrevious(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "vector.toml")

	// Write a "previous" config
	previousContent := "# previous vector config"
	if err := os.WriteFile(configPath, []byte(previousContent), 0644); err != nil {
		t.Fatalf("write previous config: %v", err)
	}

	// Create a health server that always returns 503
	unhealthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthyServer.Close()

	reloadCount := 0
	gen := NewVectorConfigGenerator()
	gen.ConfigPath = configPath
	gen.HealthTimeout = 500 * time.Millisecond // short timeout for test
	gen.HealthURL = unhealthyServer.URL
	gen.validateFunc = func(content string) error { return nil }
	gen.signalVector = func() error {
		reloadCount++
		return nil
	}

	cfg := SensorConfig{SeverityThreshold: 2}
	err := gen.ApplyConfig(cfg)
	if err == nil {
		t.Fatal("ApplyConfig should fail when health check fails")
	}

	// Previous config should be restored
	restored, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read restored config: %v", readErr)
	}
	if string(restored) != previousContent {
		t.Errorf("previous config should be restored, got: %s", restored)
	}

	// Vector should have been signaled twice (once for new config, once for restore)
	if reloadCount != 2 {
		t.Errorf("expected 2 reload signals (apply + restore), got %d", reloadCount)
	}
}

// TestApplyConfigHealthCheckSuccess verifies the happy path: validation passes,
// config is written, Vector becomes healthy.
func TestApplyConfigHealthCheckSuccess(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "vector.toml")

	// Create a health server that returns 200
	healthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthyServer.Close()

	gen := NewVectorConfigGenerator()
	gen.ConfigPath = configPath
	gen.HealthTimeout = 2 * time.Second
	gen.HealthURL = healthyServer.URL
	gen.validateFunc = func(content string) error { return nil }
	gen.signalVector = func() error { return nil }

	cfg := SensorConfig{
		SeverityThreshold: 1,
		Sinks: []SinkConfig{
			{Name: "es_main", Type: "elasticsearch", URI: "https://es.example.com:9200", SchemaMode: "ecs"},
		},
	}

	err := gen.ApplyConfig(cfg)
	if err != nil {
		t.Fatalf("ApplyConfig should succeed: %v", err)
	}

	// Config file should exist with generated content
	content, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read config: %v", readErr)
	}

	if !strings.Contains(string(content), "[sinks.es_main]") {
		t.Error("written config should contain the configured sink")
	}
	if !strings.Contains(string(content), "<= 1)") {
		t.Error("written config should use severity threshold 1")
	}
}

// TestApplyPoolConfigGeneratesVectorConfig verifies that applyPoolConfig
// generates Vector config from the sensor_config field (Requirement 8.1).
func TestApplyPoolConfigGeneratesVectorConfig(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	auditLog, err := audit.New(auditPath)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer auditLog.Close()

	configPath := filepath.Join(dir, "vector.toml")

	// Create a health server that returns 200
	healthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthyServer.Close()

	vectorGen := NewVectorConfigGenerator()
	vectorGen.ConfigPath = configPath
	vectorGen.HealthTimeout = 2 * time.Second
	vectorGen.HealthURL = healthyServer.URL
	vectorGen.validateFunc = func(content string) error { return nil }
	vectorGen.signalVector = func() error { return nil }

	lastKnown := filepath.Join(dir, "last-known.json")
	applier := NewApplierWithVectorGen(lastKnown, auditLog, vectorGen)

	sensorCfg := SensorConfig{
		SeverityThreshold: 1,
		Sinks: []SinkConfig{
			{Name: "splunk_prod", Type: "splunk_hec", URI: "https://splunk.example.com:8088", SchemaMode: "splunk_cim", Token: "tok123"},
		},
		DeadLetterPath:  "/var/sensor/dead-letter",
		DeadLetterMaxMB: 256,
	}

	sensorCfgJSON, _ := json.Marshal(sensorCfg)

	bundle := Bundle{
		Type:    "pool_config",
		Config:  map[string]string{"sensor_config": string(sensorCfgJSON)},
		Version: 1,
	}

	errs := applier.Apply(bundle, noopValidator{})
	if len(errs) > 0 {
		t.Fatalf("Apply returned errors: %v", errs)
	}

	// Vector config should have been generated
	content, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read vector config: %v", readErr)
	}

	if !strings.Contains(string(content), "[sinks.splunk_prod]") {
		t.Error("generated vector config should contain the splunk sink")
	}
	if !strings.Contains(string(content), "<= 1)") {
		t.Error("generated vector config should use severity threshold 1")
	}
	if !strings.Contains(string(content), "[sinks.dead_letter]") {
		t.Error("generated vector config should contain the dead-letter sink")
	}
}

// TestApplyPoolConfigSkipsStaticVectorConfig verifies that a static Vector
// config in the bundle's Config map is skipped in favor of generation.
func TestApplyPoolConfigSkipsStaticVectorConfig(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	auditLog, err := audit.New(auditPath)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer auditLog.Close()

	configPath := filepath.Join(dir, "vector.toml")

	healthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthyServer.Close()

	vectorGen := NewVectorConfigGenerator()
	vectorGen.ConfigPath = configPath
	vectorGen.HealthTimeout = 2 * time.Second
	vectorGen.HealthURL = healthyServer.URL
	vectorGen.validateFunc = func(content string) error { return nil }
	vectorGen.signalVector = func() error { return nil }

	lastKnown := filepath.Join(dir, "last-known.json")
	applier := NewApplierWithVectorGen(lastKnown, auditLog, vectorGen)

	sensorCfg := SensorConfig{SeverityThreshold: 2}
	sensorCfgJSON, _ := json.Marshal(sensorCfg)

	bundle := Bundle{
		Type: "pool_config",
		Config: map[string]string{
			VectorConfigPath: "# this static config should be skipped",
			"sensor_config":  string(sensorCfgJSON),
		},
		Version: 1,
	}

	errs := applier.Apply(bundle, noopValidator{})
	if len(errs) > 0 {
		t.Fatalf("Apply returned errors: %v", errs)
	}

	content, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read vector config: %v", readErr)
	}

	// Should contain generated content, not the static string
	if strings.Contains(string(content), "this static config should be skipped") {
		t.Error("static vector config should have been skipped in favor of generated config")
	}
	if !strings.Contains(string(content), "[sources.zeek_logs]") {
		t.Error("generated vector config should contain zeek source")
	}
}

// TestParseSensorConfig verifies JSON parsing of the sensor config.
func TestParseSensorConfig(t *testing.T) {
	input := `{
		"severity_threshold": 1,
		"alert_listener_addr": "http://10.0.0.1:9092",
		"sinks": [
			{"name": "es", "type": "elasticsearch", "uri": "https://es:9200", "schema_mode": "ecs"}
		],
		"dead_letter_path": "/tmp/dead",
		"dead_letter_max_mb": 100,
		"capture_workers": 4,
		"tpacket_block_size_mb": 8,
		"tpacket_frame_count": 4096,
		"drop_alert_thresh_pct": 0.5
	}`

	cfg, err := ParseSensorConfig(input)
	if err != nil {
		t.Fatalf("ParseSensorConfig: %v", err)
	}

	if cfg.SeverityThreshold != 1 {
		t.Errorf("SeverityThreshold: got %d, want 1", cfg.SeverityThreshold)
	}
	if cfg.AlertListenerAddr != "http://10.0.0.1:9092" {
		t.Errorf("AlertListenerAddr: got %q, want http://10.0.0.1:9092", cfg.AlertListenerAddr)
	}
	if len(cfg.Sinks) != 1 {
		t.Fatalf("Sinks: got %d, want 1", len(cfg.Sinks))
	}
	if cfg.Sinks[0].Name != "es" {
		t.Errorf("Sinks[0].Name: got %q, want es", cfg.Sinks[0].Name)
	}
	if cfg.DeadLetterPath != "/tmp/dead" {
		t.Errorf("DeadLetterPath: got %q, want /tmp/dead", cfg.DeadLetterPath)
	}
}

// TestParseSensorConfigInvalid verifies that invalid JSON returns an error.
func TestParseSensorConfigInvalid(t *testing.T) {
	_, err := ParseSensorConfig("not json")
	if err == nil {
		t.Fatal("ParseSensorConfig should fail on invalid JSON")
	}
}

// TestVectorSinkType verifies the mapping from our sink types to Vector types.
func TestVectorSinkType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"splunk_hec", "splunk_hec_logs"},
		{"cribl_http", "http"},
		{"elasticsearch", "elasticsearch"},
		{"http", "http"},
		{"s3", "aws_s3"},
		{"kafka", "kafka"},
		{"unknown", "http"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := vectorSinkType(tt.input)
			if got != tt.want {
				t.Errorf("vectorSinkType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestSchemaTransformVRL verifies that each schema mode returns a non-empty VRL snippet.
func TestSchemaTransformVRL(t *testing.T) {
	modes := []string{"raw", "ecs", "ocsf", "splunk_cim"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			vrl := schemaTransformVRL(mode)
			if vrl == "" {
				t.Errorf("schemaTransformVRL(%q) returned empty string", mode)
			}
		})
	}
}

// TestApplyConfigReloadFailureRestoresPrevious verifies that when the reload
// signal fails, the previous config is restored.
func TestApplyConfigReloadFailureRestoresPrevious(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "vector.toml")

	previousContent := "# previous config"
	if err := os.WriteFile(configPath, []byte(previousContent), 0644); err != nil {
		t.Fatalf("write previous config: %v", err)
	}

	gen := NewVectorConfigGenerator()
	gen.ConfigPath = configPath
	gen.validateFunc = func(content string) error { return nil }
	gen.signalVector = func() error { return fmt.Errorf("vector process not found") }

	cfg := SensorConfig{SeverityThreshold: 2}
	err := gen.ApplyConfig(cfg)
	if err == nil {
		t.Fatal("ApplyConfig should fail when reload fails")
	}

	restored, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read restored config: %v", readErr)
	}
	if string(restored) != previousContent {
		t.Errorf("previous config should be restored after reload failure")
	}
}

// TestProperty11_VectorConfigSinkIsolation is a property-based test that verifies
// for any sensor config bundle specifying a subset of sinks, the generated Vector
// configuration contains exactly those sinks and no others.
//
// **Validates: Requirements 8.2**
func TestProperty11_VectorConfigSinkIsolation(t *testing.T) {
	// Supported sink types and schema modes for generation.
	sinkTypes := []string{"splunk_hec", "cribl_http", "elasticsearch", "http", "s3", "kafka"}
	schemaModes := []string{"raw", "ecs", "ocsf", "splunk_cim"}

	// System sinks that are always present or conditionally present.
	// These are excluded from the user-sink equality check.
	systemSinks := map[string]bool{
		"pcap_alert_webhook": true,
		"dead_letter":        true,
	}

	// sinkSectionRe matches all [sinks.XXX] headers in the generated TOML config.
	sinkSectionRe := regexp.MustCompile(`\[sinks\.([a-zA-Z0-9_]+)\]`)

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random number of sinks (0-5).
		numSinks := rapid.IntRange(0, 5).Draw(t, "numSinks")

		// Track generated sink names to ensure uniqueness.
		usedNames := map[string]bool{}
		var sinks []SinkConfig

		for i := 0; i < numSinks; i++ {
			// Generate a unique sink name that doesn't collide with system sinks.
			var name string
			for {
				name = rapid.StringMatching(`[a-z][a-z0-9_]{2,15}`).Draw(t, fmt.Sprintf("sinkName_%d", i))
				if !usedNames[name] && !systemSinks[name] {
					break
				}
			}
			usedNames[name] = true

			sinkType := rapid.SampledFrom(sinkTypes).Draw(t, fmt.Sprintf("sinkType_%d", i))
			uri := rapid.StringMatching(`https://[a-z]{3,10}\.[a-z]{2,5}:[0-9]{2,5}`).Draw(t, fmt.Sprintf("uri_%d", i))
			schemaMode := rapid.SampledFrom(schemaModes).Draw(t, fmt.Sprintf("schemaMode_%d", i))

			sink := SinkConfig{
				Name:       name,
				Type:       sinkType,
				URI:        uri,
				SchemaMode: schemaMode,
			}

			// Optionally add a token.
			if rapid.Bool().Draw(t, fmt.Sprintf("hasToken_%d", i)) {
				sink.Token = rapid.StringMatching(`[a-zA-Z0-9]{8,32}`).Draw(t, fmt.Sprintf("token_%d", i))
			}

			sinks = append(sinks, sink)
		}

		// Randomly include or exclude DeadLetterPath.
		hasDeadLetter := rapid.Bool().Draw(t, "hasDeadLetter")
		deadLetterPath := ""
		if hasDeadLetter {
			deadLetterPath = rapid.StringMatching(`/var/sensor/dead-letter-[a-z]{1,8}`).Draw(t, "deadLetterPath")
		}

		cfg := SensorConfig{
			SeverityThreshold: rapid.IntRange(1, 3).Draw(t, "severityThreshold"),
			Sinks:             sinks,
			DeadLetterPath:    deadLetterPath,
		}

		gen := NewVectorConfigGenerator()
		content, err := gen.GenerateConfig(cfg)
		if err != nil {
			t.Fatalf("GenerateConfig failed: %v", err)
		}

		// Extract all sink names from [sinks.XXX] sections in the generated config.
		matches := sinkSectionRe.FindAllStringSubmatch(content, -1)
		foundSinks := map[string]bool{}
		for _, m := range matches {
			foundSinks[m[1]] = true
		}

		// 1. pcap_alert_webhook must always be present (system sink).
		if !foundSinks["pcap_alert_webhook"] {
			t.Fatal("pcap_alert_webhook system sink must always be present in generated config")
		}

		// 2. dead_letter must be present iff DeadLetterPath is non-empty.
		if hasDeadLetter && !foundSinks["dead_letter"] {
			t.Fatal("dead_letter sink must be present when DeadLetterPath is configured")
		}
		if !hasDeadLetter && foundSinks["dead_letter"] {
			t.Fatal("dead_letter sink must NOT be present when DeadLetterPath is not configured")
		}

		// 3. The set of user sinks in the config must equal exactly the set of
		//    sink names from the input (excluding system sinks).
		var configUserSinks []string
		for name := range foundSinks {
			if !systemSinks[name] {
				configUserSinks = append(configUserSinks, name)
			}
		}
		sort.Strings(configUserSinks)

		var inputSinkNames []string
		for _, s := range sinks {
			inputSinkNames = append(inputSinkNames, s.Name)
		}
		sort.Strings(inputSinkNames)

		// Handle nil vs empty slice comparison.
		if len(configUserSinks) == 0 && len(inputSinkNames) == 0 {
			return // both empty, pass
		}

		if len(configUserSinks) != len(inputSinkNames) {
			t.Fatalf("user sink count mismatch: config has %v, input has %v",
				configUserSinks, inputSinkNames)
		}

		for i := range configUserSinks {
			if configUserSinks[i] != inputSinkNames[i] {
				t.Fatalf("user sink mismatch at index %d: config has %q, input has %q\nconfig sinks: %v\ninput sinks: %v",
					i, configUserSinks[i], inputSinkNames[i], configUserSinks, inputSinkNames)
			}
		}
	})
}
