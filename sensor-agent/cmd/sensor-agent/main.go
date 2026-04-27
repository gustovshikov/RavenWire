//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sensor-stack/sensor-agent/internal/api"
	"github.com/sensor-stack/sensor-agent/internal/audit"
	"github.com/sensor-stack/sensor-agent/internal/capture"
	"github.com/sensor-stack/sensor-agent/internal/certs"
	"github.com/sensor-stack/sensor-agent/internal/config"
	"github.com/sensor-stack/sensor-agent/internal/health"
	"github.com/sensor-stack/sensor-agent/internal/pcap"
	"github.com/sensor-stack/sensor-agent/internal/readiness"
	"github.com/sensor-stack/sensor-agent/internal/rules"
	"github.com/sensor-stack/sensor-agent/internal/support"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("sensor-agent: starting")

	// ── Configuration from environment ───────────────────────────────────────
	controlPort := envOrDefault("CONTROL_API_PORT", "9091")
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
	checker := readiness.New(readinessCfg)

	log.Println("sensor-agent: running host readiness checks")
	report := checker.Check()
	for _, ch := range report.Checks {
		status := "PASS"
		if !ch.Passed {
			status = "FAIL"
		}
		log.Printf("  [%s] %s: %s", status, ch.Name, ch.Message)
	}
	if !report.Passed {
		log.Fatal("sensor-agent: host readiness check failed; capture will not start")
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

	// ── Module 9: SQLite PCAP Index ───────────────────────────────────────────
	pcapIndex, err := pcap.OpenIndex(pcapDBPath)
	if err != nil {
		log.Fatalf("sensor-agent: failed to open PCAP index: %v", err)
	}
	defer pcapIndex.Close()

	// ── Module 5: PCAP Manager ────────────────────────────────────────────────
	pcapManager := pcap.NewManager(pcapRingSock, pcapAlertsDir, pcapIndex, auditLog)

	// ── Module 6: Rule Validator ──────────────────────────────────────────────
	ruleValidator := rules.NewValidator()

	// ── Module 7: Certificate Manager ────────────────────────────────────────
	certManager := certs.NewManager(certDir, configManagerURL, podName, enrollmentToken, auditLog)
	if enrollmentToken != "" {
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

	// ── Module 3: Health Collector ────────────────────────────────────────────
	healthCollector := health.NewCollector(captureManager, auditLog)

	// ── Module 10: Support Bundle ─────────────────────────────────────────────
	bundleGen := support.NewBundleGenerator(auditLog)

	// ── Module 1: Control API ─────────────────────────────────────────────────
	certFile := certDir + "/sensor.crt"
	keyFile := certDir + "/sensor.key"
	caFile := certDir + "/ca-chain.pem"

	var apiServer *api.Server
	if fileExists(certFile) && fileExists(keyFile) && fileExists(caFile) {
		mtlsCfg, err := api.NewMTLSConfig(certFile, keyFile, caFile)
		if err != nil {
			log.Printf("sensor-agent: mTLS config failed (falling back to plain HTTP): %v", err)
			apiServer = api.New(":"+controlPort, nil, auditLog)
		} else {
			apiServer = api.New(":"+controlPort, mtlsCfg, auditLog)
		}
	} else {
		log.Printf("sensor-agent: certs not found at %s, starting without mTLS (enrollment required)", certDir)
		apiServer = api.New(":"+controlPort, nil, auditLog)
	}

	// Register control handlers
	registerHandlers(apiServer, captureManager, pcapManager, configApplier, ruleValidator, certManager, healthCollector, bundleGen, auditLog)

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

	go func() {
		if err := apiServer.ListenAndServe(); err != nil {
			log.Printf("sensor-agent: control API stopped: %v", err)
		}
	}()

	log.Printf("sensor-agent: ready (control API on :%s)", controlPort)

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
		podmanSock := envOrDefault("PODMAN_SOCKET_PATH", "/run/podman/podman.sock")
		if err := restartContainerViaPodman(podmanSock, "vector"); err != nil {
			auditLog.Log("restart-vector", actorFrom(r), "failure", map[string]any{"error": err.Error()})
			writeErr(w, 500, err.Error())
			return
		}
		auditLog.Log("restart-vector", actorFrom(r), "success", nil)
		writeOK(w)
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func restartContainerViaPodman(sockPath, containerName string) error {
	log.Printf("sensor-agent: restarting container %q via Podman socket %s", containerName, sockPath)
	// TODO: implement Podman REST API call via Unix socket
	return nil
}
