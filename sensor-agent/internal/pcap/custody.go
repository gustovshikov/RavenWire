package pcap

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// CustodyEventType identifies the kind of chain-of-custody event.
type CustodyEventType string

const (
	// CustodyEventCreated is recorded when a PCAP file is carved.
	CustodyEventCreated CustodyEventType = "created"
	// CustodyEventAccessed is recorded when a PCAP file is accessed via the API.
	CustodyEventAccessed CustodyEventType = "accessed"
)

// CustodyEvent is a single entry in a Chain_of_Custody_Manifest (JSON Lines).
type CustodyEvent struct {
	Event       CustodyEventType `json:"event"`
	TimestampMs int64            `json:"timestamp_ms"`
	Actor       string           `json:"actor"`

	// Fields present only on "created" events.
	AlertSID  string `json:"alert_sid,omitempty"`
	AlertUUID string `json:"alert_uuid,omitempty"`
	FileHash  string `json:"file_hash,omitempty"`

	// Fields present only on "accessed" events.
	Purpose string `json:"purpose,omitempty"`
}

// manifestMu serialises concurrent appends to the same manifest file.
// Keyed by absolute manifest path.
var manifestMu sync.Map

// lockManifest returns a mutex for the given manifest path, creating one if
// needed. This prevents concurrent goroutines from interleaving writes.
func lockManifest(path string) *sync.Mutex {
	v, _ := manifestMu.LoadOrStore(path, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// HashFile computes the SHA256 hash of the file at path and returns it as a
// hex-encoded string prefixed with "sha256:".
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for hashing: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

// FileSizeBytes returns the size of the file at path in bytes.
func FileSizeBytes(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat file: %w", err)
	}
	return info.Size(), nil
}

// ManifestPathForPcap returns the chain-of-custody manifest path for a given
// PCAP file path. The manifest is stored alongside the PCAP with a
// ".custody.jsonl" suffix.
func ManifestPathForPcap(pcapPath string) string {
	return pcapPath + ".custody.jsonl"
}

// WriteCreatedManifest creates a new Chain_of_Custody_Manifest for a carved
// PCAP file, recording the initial "created" event with the carve details.
// The manifest is a JSON Lines file (one JSON object per line).
func WriteCreatedManifest(manifestPath string, actor, alertSID, alertUUID, fileHash string) error {
	event := CustodyEvent{
		Event:       CustodyEventCreated,
		TimestampMs: time.Now().UnixMilli(),
		Actor:       actor,
		AlertSID:    alertSID,
		AlertUUID:   alertUUID,
		FileHash:    fileHash,
	}
	return writeManifestEvent(manifestPath, event, true)
}

// AppendAccessEvent appends an "accessed" event to an existing
// Chain_of_Custody_Manifest, recording who accessed the file, when, and why.
func AppendAccessEvent(manifestPath, actor, purpose string) error {
	event := CustodyEvent{
		Event:       CustodyEventAccessed,
		TimestampMs: time.Now().UnixMilli(),
		Actor:       actor,
		Purpose:     purpose,
	}
	return writeManifestEvent(manifestPath, event, false)
}

// writeManifestEvent serialises a CustodyEvent as a single JSON line and
// writes it to the manifest file. If create is true the file is created
// (truncating any existing content); otherwise it is opened for append.
func writeManifestEvent(manifestPath string, event CustodyEvent, create bool) error {
	mu := lockManifest(manifestPath)
	mu.Lock()
	defer mu.Unlock()

	flags := os.O_WRONLY | os.O_CREATE
	if create {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_APPEND
	}

	f, err := os.OpenFile(manifestPath, flags, 0640)
	if err != nil {
		return fmt.Errorf("open manifest %s: %w", manifestPath, err)
	}
	defer f.Close()

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal custody event: %w", err)
	}
	data = append(data, '\n')

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write custody event: %w", err)
	}
	return nil
}

// ReadManifest reads all events from a Chain_of_Custody_Manifest file.
func ReadManifest(manifestPath string) ([]CustodyEvent, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", manifestPath, err)
	}

	var events []CustodyEvent
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			line := data[start:i]
			start = i + 1
			if len(line) == 0 {
				continue
			}
			var ev CustodyEvent
			if err := json.Unmarshal(line, &ev); err != nil {
				return nil, fmt.Errorf("unmarshal custody event: %w", err)
			}
			events = append(events, ev)
		}
	}
	// Handle last line without trailing newline.
	if start < len(data) {
		line := data[start:]
		if len(line) > 0 {
			var ev CustodyEvent
			if err := json.Unmarshal(line, &ev); err != nil {
				return nil, fmt.Errorf("unmarshal custody event: %w", err)
			}
			events = append(events, ev)
		}
	}
	return events, nil
}
