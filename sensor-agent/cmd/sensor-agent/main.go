//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/api"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/bootstrap"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/capture"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/certs"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/config"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/health"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/pcap"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/podman"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/readiness"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/rules"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/support"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("sensor-agent: starting")

	// ── Configuration from environment ───────────────────────────────────────
	controlPort := envOrDefault("CONTROL_API_PORT", "9091")
	enrollmentPort := envOrDefault("ENROLLMENT_PORT", "9090")
	devMode := os.Getenv("SENSOR_DEV_MODE") == "true"
	configManagerURL := envOrDefault("CONFIG_MANAGER_URL", "")
	grpcAddr := envOrDefault("GRPC_ADDR", "") // host:port for gRPC health stream; defaults to CONFIG_MANAGER_URL if empty
	if grpcAddr == "" {
		grpcAddr = configManagerURL
	}
	captureConfigPath := envOrDefault("CAPTURE_CONFIG_PATH", capture.DefaultCaptureConfigPath)
	bpfFilterPath := envOrDefault("BPF_FILTER_PATH", "/etc/sensor/bpf_filters.conf")
	pcapRingSock := envOrDefault("PCAP_RING_SOCK", "/var/run/pcap_ring.sock")
	auditLogPath := envOrDefault("AUDIT_LOG_PATH", "/var/sensor/audit.log")
	certDir := envOrDefault("CERT_DIR", "/etc/sensor/certs")
	enrollmentToken := os.Getenv("SENSOR_ENROLLMENT_TOKEN")
	podName := envOrDefault("SENSOR_POD_NAME", "sensor-pod")
	pcapAlertsDir := envOrDefault("PCAP_ALERTS_DIR", "/sensor/pcap/alerts")
	pcapDBPath := envOrDefault("PCAP_DB_PATH", "/sensor/pcap/pcap.db")
	alertListenerAddr := envOrDefault("ALERT_LISTENER_ADDR", ":9092")
	healthBufferPath := envOrDefault("HEALTH_BUFFER_PATH", "/var/sensor/health-buffer.bin")
	lastKnownConfigPath := envOrDefault("LAST_KNOWN_CONFIG_PATH", "/etc/sensor/last-known-config.json")
	captureIface := envOrDefault("CAPTURE_IFACE", "eth0")

	// ── Module 8: Local Audit Logger ─────────────────────────────────────────
	auditLog, err := audit.New(auditLogPath)
	if err != nil {
		log.Fatalf("sensor-agent: failed to open audit log: %v", err)
	}
	defer auditLog.Close()
	auditLog.Log("startup", "system", "success", map[string]any{"pod_name": podName})

	// ── Module 9: Host Readiness Checker ─────────────────────────────────────
	readinessCfg := readiness.DefaultConfig()
	readinessCfg.Interface = captureIface
	if minDiskWriteMBps, ok := envFloat("MIN_DISK_WRITE_MBPS"); ok {
		readinessCfg.MinDiskWriteMBps = minDiskWriteMBps
	}
	if minStorageGB, ok := envFloat("MIN_STORAGE_GB"); ok {
		readinessCfg.MinStorageGB = minStorageGB
	}
	if cpuList := os.Getenv("CAPTURE_CPU_LIST"); cpuList != "" {
		readinessCfg.CaptureCPUList = cpuList
	}
	checker := readiness.New(readinessCfg)

	// ── Bootstrap State Machine (Requirement 11) ─────────────────────────────
	// When an enrollment token is present and no certs exist, run the full
	// bootstrap state machine: installed → enrolling → pending_approval →
	// config_received → config_validated → capture_active.
	certFile := certDir + "/sensor.crt"
	keyFile := certDir + "/sensor.key"
	caFile := certDir + "/ca-chain.pem"

	if enrollmentToken != "" && configManagerURL != "" && !fileExists(certFile) {
		log.Println("sensor-agent: fresh install detected — running bootstrap state machine")

		ruleValidator := rules.NewValidator()
		bootstrapMachine := bootstrap.NewMachine(bootstrap.Config{
			ConfigManagerURL: configManagerURL,
			EnrollmentToken:  enrollmentToken,
			PodName:          podName,
			CertDir:          certDir,
			Validator:        &bootstrapConfigValidator{ruleValidator: ruleValidator},
			Readiness:        &bootstrapReadinessAdapter{checker: checker},
			Writer:           &bootstrapConfigWriter{lastKnownConfigPath: lastKnownConfigPath, auditLog: auditLog},
			AuditLog:         auditLog,
		})

		ctx, cancel := context.WithCancel(context.Background())
		// Cancel bootstrap on SIGINT/SIGTERM
		go func() {
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			<-sigCh
			cancel()
		}()

		if err := bootstrapMachine.Run(ctx); err != nil {
			log.Fatalf("sensor-agent: bootstrap failed: %v", err)
		}
		cancel() // clean up signal goroutine

		log.Printf("sensor-agent: bootstrap complete (state=%s)", bootstrapMachine.State())
	}

	log.Println("sensor-agent: running host readiness checks")
	report := checker.Check()
	for _, ch := range report.Checks {
		status := "PASS"
		if !ch.Passed {
			if ch.Severity == readiness.SeverityHard {
				status = "FAIL"
			} else {
				status = "WARN"
			}
		}
		log.Printf("  [%s] [%s] %s: %s (observed=%s, required=%s)",
			status, ch.Severity, ch.Name, ch.Message, ch.ObservedValue, ch.RequiredValue)
	}
	if !report.Passed {
		log.Fatal("sensor-agent: host readiness check failed (hard failure); capture will not start")
	}
	log.Println("sensor-agent: host readiness checks passed")

	// ── Module 2: Capture Manager ─────────────────────────────────────────────
	captureCfg, err := capture.LoadCaptureConfig(captureConfigPath)
	if err != nil {
		log.Fatalf("sensor-agent: failed to load capture config: %v", err)
	}
	captureCfg.OverrideInterface(captureIface)
	if errs := captureCfg.Validate(); len(errs) > 0 {
		for _, e := range errs {
			log.Printf("sensor-agent: capture config error: %v", e)
		}
		log.Fatal("sensor-agent: invalid capture configuration; aborting")
	}
	captureManager := capture.NewManager(captureCfg, bpfFilterPath, pcapRingSock)

	// ── Module 6: Rule Validator ──────────────────────────────────────────────
	ruleValidator := rules.NewValidator()

	// ── Module 7: Certificate Manager ────────────────────────────────────────
	certManager := certs.NewManager(certDir, configManagerURL, podName, enrollmentToken, auditLog)
	certsPresent := fileExists(certFile) && fileExists(keyFile) && fileExists(caFile)
	if enrollmentToken != "" && !certsPresent {
		log.Println("sensor-agent: enrollment token present, initiating enrollment")
		if err := certManager.Enroll(); err != nil {
			log.Printf("sensor-agent: enrollment failed (will retry): %v", err)
		}
	} else {
		if err := certManager.LoadExisting(); err != nil {
			log.Printf("sensor-agent: no existing cert found (enrollment required): %v", err)
		}
	}

	// ── Module 4: Config Applier ──────────────────────────────────────────────
	configApplier := config.NewApplier(lastKnownConfigPath, auditLog)
	if err := configApplier.LoadLastKnown(); err != nil {
		log.Printf("sensor-agent: no last-known config (fresh start): %v", err)
	}

	// ── Module 11: Podman Client ──────────────────────────────────────────────
	podmanSockPath := envOrDefault("PODMAN_SOCKET_PATH", "/run/podman/podman.sock")
	// Allowlist maps container name → Quadlet unit name (empty = use Podman API directly).
	// Quadlet unit names follow the pattern "<container>.service".
	podmanAllowlist := map[string]string{
		"vector":           "vector.service",
		"zeek":             "zeek.service",
		"suricata":         "suricata.service",
		"pcap_ring_writer": "pcap-ring-writer.service",
		"pcap-ring-writer": "pcap-ring-writer.service",
		"netsniff-ng":      "netsniff-ng.service",
	}
	podmanClient := podman.New(podman.Config{
		SocketPath: podmanSockPath,
		Allowlist:  podmanAllowlist,
		AuditLog:   auditLog,
	})

	// ── Module 9: SQLite PCAP Index ───────────────────────────────────────────
	pcapIndex, err := pcap.OpenIndex(pcapDBPath)
	if err != nil {
		log.Fatalf("sensor-agent: failed to open PCAP index: %v", err)
	}
	defer pcapIndex.Close()

	// ── Module 5: PCAP Manager ────────────────────────────────────────────────
	// Load severity threshold from the last-known sensor config so the PCAP Manager
	// uses the same threshold as the generated Vector config (Requirement 3.4, 8.3).
	pcapManagerCfg := pcap.ManagerConfig{
		SensorID:        podName,
		PodmanClient:    podmanClient,
		PCAPStoragePath: pcapAlertsDir,
	}
	if sensorCfg, ok := configApplier.SensorConfig(); ok {
		pcapManagerCfg.SeverityThreshold = sensorCfg.SeverityThreshold
		log.Printf("sensor-agent: PCAP Manager severity threshold set to %d from sensor config", sensorCfg.SeverityThreshold)
	}
	pcapManager := pcap.NewManagerWithConfig(pcapRingSock, pcapAlertsDir, pcapIndex, auditLog, pcapManagerCfg)

	// ── Module 3: Health Collector ────────────────────────────────────────────
	healthCollector := health.NewCollector(captureManager, auditLog)

	// ── Module 10: Support Bundle ─────────────────────────────────────────────
	bundleGen := support.NewBundleGenerator(auditLog)

	// ── Module 1: Control API ─────────────────────────────────────────────────
	// certFile, keyFile, caFile already declared above (bootstrap section).

	// Requirement 6.2: Log prominent warning when SENSOR_DEV_MODE=true.
	if devMode {
		log.Println("sensor-agent: *** WARNING: SENSOR_DEV_MODE=true — mTLS is DISABLED. This deployment is NOT production-safe. ***")
		auditLog.Log("dev-mode-warning", "system", "warning", map[string]any{
			"message": "SENSOR_DEV_MODE=true: mTLS disabled, deployment is not production-safe",
		})
	}

	var apiServer *api.Server
	if fileExists(certFile) && fileExists(keyFile) && fileExists(caFile) {
		mtlsCfg, err := api.NewMTLSConfig(certFile, keyFile, caFile)
		if err != nil {
			// Requirement 6.1: Fail startup if mTLS config fails and not in dev mode.
			if !devMode {
				log.Fatalf("sensor-agent: FATAL: mTLS config failed and SENSOR_DEV_MODE is not set: %v", err)
			}
			log.Printf("sensor-agent: mTLS config failed (dev mode — falling back to plain HTTP): %v", err)
			apiServer = api.New(":"+controlPort, nil, auditLog)
		} else {
			apiServer = api.New(":"+controlPort, mtlsCfg, auditLog)
		}
	} else {
		// Requirement 6.1: Certs absent — fail unless SENSOR_DEV_MODE=true.
		if !devMode {
			log.Fatalf("sensor-agent: FATAL: certificates not found at %s and SENSOR_DEV_MODE is not set; "+
				"set SENSOR_DEV_MODE=true to allow plain HTTP for development", certDir)
		}
		log.Printf("sensor-agent: certs not found at %s (dev mode — starting without mTLS)", certDir)
		apiServer = api.New(":"+controlPort, nil, auditLog)
	}

	// Register control handlers
	registerHandlers(apiServer, captureManager, pcapManager, configApplier, ruleValidator, certManager, healthCollector, bundleGen, podmanClient, auditLog)

	// ── Start background goroutines ───────────────────────────────────────────
	done := make(chan struct{})

	go func() {
		if err := captureManager.WatchBPFFilter(done); err != nil {
			log.Printf("sensor-agent: BPF filter watcher stopped: %v", err)
		}
	}()

	if configManagerURL != "" {
		streamClient := health.NewStreamClient(grpcAddr, certDir, healthBufferPath, healthCollector, auditLog)
		go func() { streamClient.Run(done) }()
	}

	go func() { certManager.MonitorExpiry(done) }()

	// ── Start Alert_Listener before declaring control API ready ──────────────
	pcapManager.ListenForAlerts(alertListenerAddr, done)

	// ── Start enrollment listener on separate port (Requirement 6.7) ─────────
	enrollmentListener := api.NewEnrollmentListener(":"+enrollmentPort, func(w http.ResponseWriter, r *http.Request) {
		if err := certManager.Enroll(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "enrolled"})
	})
	go func() {
		if err := enrollmentListener.ListenAndServe(); err != nil {
			log.Printf("sensor-agent: enrollment listener stopped: %v", err)
		}
	}()

	go func() {
		if err := apiServer.ListenAndServe(); err != nil {
			log.Printf("sensor-agent: control API stopped: %v", err)
		}
	}()

	log.Printf("sensor-agent: ready (control API on :%s, enrollment on :%s, alert listener on %s)",
		controlPort, enrollmentPort, alertListenerAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("sensor-agent: shutting down")
	close(done)
	auditLog.Log("shutdown", "system", "success", nil)
}

func registerHandlers(
	srv *api.Server,
	capMgr *capture.Manager,
	pcapMgr *pcap.Manager,
	cfgApplier *config.Applier,
	ruleVal *rules.Validator,
	certMgr *certs.Manager,
	healthCol *health.Collector,
	bundleGen *support.BundleGenerator,
	podmanClient *podman.Client,
	auditLog *audit.Logger,
) {
	srv.Register("reload-zeek", func(w http.ResponseWriter, r *http.Request) {
		if err := capture.SendSignalByName("zeek", syscall.SIGHUP); err != nil {
			auditLog.Log("reload-zeek", actorFrom(r), "failure", map[string]any{"error": err.Error()})
			writeErr(w, 500, err.Error())
			return
		}
		auditLog.Log("reload-zeek", actorFrom(r), "success", nil)
		writeOK(w)
	})

	srv.Register("reload-suricata", func(w http.ResponseWriter, r *http.Request) {
		if err := capture.SendSignalByName("suricata", syscall.SIGUSR2); err != nil {
			auditLog.Log("reload-suricata", actorFrom(r), "failure", map[string]any{"error": err.Error()})
			writeErr(w, 500, err.Error())
			return
		}
		auditLog.Log("reload-suricata", actorFrom(r), "success", nil)
		writeOK(w)
	})

	srv.Register("restart-vector", func(w http.ResponseWriter, r *http.Request) {
		actor := actorFrom(r)
		result, err := podmanClient.RestartContainer("vector", actor)
		if err != nil {
			auditLog.Log("restart-vector", actor, "failure", map[string]any{"error": err.Error()})
			writeErr(w, 500, err.Error())
			return
		}
		auditLog.Log("restart-vector", actor, "success", map[string]any{
			"method": result.Method,
			"state":  string(result.State),
		})
		writeJSON(w, map[string]string{"status": "ok", "state": string(result.State), "method": result.Method})
	})

	srv.Register("switch-capture-mode", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mode string `json:"mode"`
		}
		if err := decodeBody(r.Body, &req); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if err := pcapMgr.SwitchMode(req.Mode); err != nil {
			auditLog.Log("switch-capture-mode", actorFrom(r), "failure", map[string]any{"error": err.Error()})
			writeErr(w, 500, err.Error())
			return
		}
		auditLog.Log("switch-capture-mode", actorFrom(r), "success", map[string]any{"mode": req.Mode})
		writeJSON(w, map[string]string{"status": "ok", "mode": req.Mode})
	})

	srv.Register("apply-pool-config", func(w http.ResponseWriter, r *http.Request) {
		var bundle config.Bundle
		if err := decodeBody(r.Body, &bundle); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if errs := cfgApplier.Apply(bundle, ruleVal); len(errs) > 0 {
			auditLog.Log("apply-pool-config", actorFrom(r), "failure", map[string]any{"errors": errs})
			writeErr(w, 422, fmt.Sprintf("validation failed: %v", errs))
			return
		}
		auditLog.Log("apply-pool-config", actorFrom(r), "success", nil)
		writeOK(w)
	})

	srv.Register("rotate-cert", func(w http.ResponseWriter, r *http.Request) {
		if err := certMgr.Rotate(); err != nil {
			auditLog.Log("rotate-cert", actorFrom(r), "failure", map[string]any{"error": err.Error()})
			writeErr(w, 500, err.Error())
			return
		}
		auditLog.Log("rotate-cert", actorFrom(r), "success", nil)
		writeOK(w)
	})

	srv.Register("report-health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, healthCol.Collect())
	})

	srv.Register("carve-pcap", func(w http.ResponseWriter, r *http.Request) {
		var req pcap.CarveRequest
		if err := decodeBody(r.Body, &req); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		result, err := pcapMgr.Carve(req)
		if err != nil {
			auditLog.Log("carve-pcap", actorFrom(r), "failure", map[string]any{"error": err.Error()})
			writeErr(w, 500, err.Error())
			return
		}
		auditLog.Log("carve-pcap", actorFrom(r), "success", map[string]any{"output": result.OutputPath})
		writeJSON(w, result)
	})

	srv.Register("validate-config", func(w http.ResponseWriter, r *http.Request) {
		var bundle config.Bundle
		if err := decodeBody(r.Body, &bundle); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		errs := ruleVal.ValidateBundle(bundle)
		if len(errs) > 0 {
			auditLog.Log("validate-config", actorFrom(r), "failure", map[string]any{"errors": errs})
			writeJSON(w, map[string]any{"valid": false, "errors": errs})
			return
		}
		auditLog.Log("validate-config", actorFrom(r), "success", nil)
		writeJSON(w, map[string]any{"valid": true})
	})

	srv.Register("support-bundle", func(w http.ResponseWriter, r *http.Request) {
		path, err := bundleGen.Generate()
		if err != nil {
			auditLog.Log("support-bundle", actorFrom(r), "failure", map[string]any{"error": err.Error()})
			writeErr(w, 500, err.Error())
			return
		}
		auditLog.Log("support-bundle", actorFrom(r), "success", map[string]any{"path": path})
		writeJSON(w, map[string]string{"status": "ok", "path": path, "bundle_path": path})
	})

	srv.Register("download-support-bundle", func(w http.ResponseWriter, r *http.Request) {
		bundlePath := r.URL.Query().Get("path")
		if bundlePath == "" {
			writeErr(w, 400, "path query parameter is required")
			return
		}
		f, err := os.Open(bundlePath)
		if err != nil {
			auditLog.Log("download-support-bundle", actorFrom(r), "failure", map[string]any{"error": err.Error()})
			writeErr(w, 404, fmt.Sprintf("bundle not found: %v", err))
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(bundlePath)))
		if _, err := io.Copy(w, f); err != nil {
			log.Printf("sensor-agent: download-support-bundle: write error: %v", err)
		}
		auditLog.Log("download-support-bundle", actorFrom(r), "success", map[string]any{"path": bundlePath})
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func actorFrom(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return "unknown"
}

func writeOK(w http.ResponseWriter) {
	writeJSON(w, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": msg}})
}

func decodeBody(body io.Reader, v any) error {
	return json.NewDecoder(body).Decode(v)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envFloat(key string) (float64, bool) {
	v := os.Getenv(key)
	if v == "" {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(v, 64)
	if err != nil {
		log.Printf("sensor-agent: invalid %s=%q: %v", key, v, err)
		return 0, false
	}
	return parsed, true
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ── Bootstrap adapter types ──────────────────────────────────────────────────

// bootstrapConfigValidator adapts the rules.Validator to the bootstrap.ConfigValidator interface.
type bootstrapConfigValidator struct {
	ruleValidator *rules.Validator
}

func (v *bootstrapConfigValidator) ValidateBundle(configJSON string) []string {
	// Parse the config JSON to validate it's well-formed.
	_, err := config.ParseSensorConfig(configJSON)
	if err != nil {
		return []string{fmt.Sprintf("invalid sensor config: %v", err)}
	}

	// Validate as a pool_config bundle.
	bundle := config.Bundle{
		Type:    "pool_config",
		Config:  map[string]string{"sensor_config": configJSON},
		Version: 1,
	}
	return v.ruleValidator.ValidateBundle(bundle)
}

// bootstrapReadinessAdapter adapts the readiness.Checker to the bootstrap.ReadinessChecker interface.
type bootstrapReadinessAdapter struct {
	checker *readiness.Checker
}

func (a *bootstrapReadinessAdapter) CheckHardFailures() (bool, []string) {
	report := a.checker.Check()
	var failures []string
	for _, ch := range report.Checks {
		if !ch.Passed && ch.Severity == readiness.SeverityHard {
			failures = append(failures, fmt.Sprintf("%s: %s (observed=%s, required=%s)",
				ch.Name, ch.Message, ch.ObservedValue, ch.RequiredValue))
		}
	}
	return report.Passed, failures
}

// bootstrapConfigWriter adapts the config applier to the bootstrap.ConfigWriter interface.
type bootstrapConfigWriter struct {
	lastKnownConfigPath string
	auditLog            *audit.Logger
}

func (w *bootstrapConfigWriter) WriteConfigAndStartCapture(bundle bootstrap.ConfigBundle) error {
	if bundle.ConfigJSON == "" {
		return nil
	}

	// Persist the config bundle as the last-known config.
	configBundle := config.Bundle{
		Type:    "pool_config",
		Config:  map[string]string{"sensor_config": bundle.ConfigJSON},
		Version: 1,
	}

	vectorGen := config.NewVectorConfigGenerator()
	vectorGen.SkipReload = true
	applier := config.NewApplierWithVectorGen(w.lastKnownConfigPath, w.auditLog, vectorGen)
	validator := rules.NewValidator()
	if errs := applier.Apply(configBundle, validator); len(errs) > 0 {
		return fmt.Errorf("apply config: %v", errs)
	}

	return nil
}
