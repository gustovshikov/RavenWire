package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry is a single audit log record.
type Entry struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Result    string         `json:"result"`
	Detail    map[string]any `json:"detail,omitempty"`
}

// Logger is an append-only JSON-lines audit logger.
type Logger struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// New opens (or creates) the audit log file at path.
func New(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	return &Logger{path: path, f: f}, nil
}

// Log appends a JSON-lines audit entry. Thread-safe.
func (l *Logger) Log(action, actor, result string, detail map[string]any) {
	entry := Entry{
		ID:        newID(),
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Action:    action,
		Result:    result,
		Detail:    detail,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.f.Write(data)
	l.f.Write([]byte("\n"))
}

// Close flushes and closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// ReadLast returns the last n lines from the audit log.
func (l *Logger) ReadLast(n int) ([]Entry, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}

	lines := splitLines(string(data))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	var entries []Entry
	for _, line := range lines {
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err == nil {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// newID generates a simple unique ID using timestamp + random suffix.
func newID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
