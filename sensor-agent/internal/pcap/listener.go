package pcap

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync/atomic"
)

const (
	defaultAlertQueueSize = 1024
	defaultListenerAddr   = ":9092"
)

// AlertListener is the HTTP server that receives Suricata EVE JSON alert
// payloads forwarded by Vector and enqueues them for processing.
type AlertListener struct {
	addr    string
	queue   chan AlertEvent
	manager *Manager

	// dedup cache size is tracked atomically for the health endpoint
	dedupSize atomic.Int64

	server *http.Server
}

// NewAlertListener creates an AlertListener bound to addr (default ":9092").
// queueSize controls the bounded queue depth; 0 uses the default (1024).
func NewAlertListener(addr string, queueSize int, manager *Manager) *AlertListener {
	if addr == "" {
		addr = defaultListenerAddr
	}
	if queueSize <= 0 {
		queueSize = defaultAlertQueueSize
	}
	al := &AlertListener{
		addr:    addr,
		queue:   make(chan AlertEvent, queueSize),
		manager: manager,
	}
	return al
}

// Start begins serving HTTP requests. It returns immediately; the server runs
// in a background goroutine. Call Shutdown to stop it.
func (al *AlertListener) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /alerts", al.handlePostAlerts)
	mux.HandleFunc("GET /alerts/health", al.handleHealth)

	al.server = &http.Server{
		Addr:    al.addr,
		Handler: mux,
	}

	go func() {
		log.Printf("pcap: alert listener starting on %s", al.addr)
		if err := al.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("pcap: alert listener error: %v", err)
		}
	}()
}

// Shutdown gracefully stops the HTTP server.
func (al *AlertListener) Shutdown(ctx context.Context) error {
	if al.server != nil {
		return al.server.Shutdown(ctx)
	}
	return nil
}

// Queue returns the read side of the alert queue so the Manager can drain it.
func (al *AlertListener) Queue() <-chan AlertEvent {
	return al.queue
}

// QueueDepth returns the current number of pending alerts in the queue.
func (al *AlertListener) QueueDepth() int {
	return len(al.queue)
}

// SetDedupSize updates the deduplication cache size reported by the health endpoint.
func (al *AlertListener) SetDedupSize(n int64) {
	al.dedupSize.Store(n)
}

// handlePostAlerts handles POST /alerts.
func (al *AlertListener) handlePostAlerts(w http.ResponseWriter, r *http.Request) {
	var event AlertEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if event.CommunityID == "" || event.Severity == 0 || event.TimestampMs == 0 || event.SID == "" {
		log.Printf("pcap: alert listener: rejected invalid payload community_id=%q sid=%q severity=%d timestamp_ms=%d",
			event.CommunityID, event.SID, event.Severity, event.TimestampMs)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"missing required fields: community_id, severity, timestamp_ms, sid"}`))
		return
	}

	// Try to enqueue; drop and return 429 if full
	select {
	case al.queue <- event:
		w.WriteHeader(http.StatusAccepted)
	default:
		log.Printf("pcap: alert listener: queue full, dropping alert community_id=%q sid=%q",
			event.CommunityID, event.SID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":"queue full"}`))
	}
}

// handleHealth handles GET /alerts/health.
func (al *AlertListener) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := struct {
		QueueDepth  int   `json:"queue_depth"`
		DedupCacheSize int64 `json:"dedup_cache_size"`
	}{
		QueueDepth:     al.QueueDepth(),
		DedupCacheSize: al.dedupSize.Load(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// alertListenerAddr is a compile-time check that the constant is a string.
var _ = defaultListenerAddr
