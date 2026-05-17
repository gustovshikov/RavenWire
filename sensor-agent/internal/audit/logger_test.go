package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLoggerWritesJSONLinesAndReadsTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer logger.Close()

	logger.Log("first", "sensor-agent", "success", map[string]any{"step": "one"})
	logger.Log("second", "sensor-agent", "failure", map[string]any{"step": "two"})
	logger.Log("third", "sensor-agent", "success", nil)

	entries, err := logger.ReadLast(2)
	if err != nil {
		t.Fatalf("ReadLast: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("ReadLast(2) returned %d entries, want 2", len(entries))
	}
	if entries[0].Action != "second" || entries[1].Action != "third" {
		t.Fatalf("tail entries = %#v", entries)
	}
	if entries[0].ID == "" || entries[0].Timestamp.IsZero() {
		t.Fatalf("entry should have id and timestamp: %#v", entries[0])
	}
	if entries[0].Detail["step"] != "two" {
		t.Fatalf("detail = %#v", entries[0].Detail)
	}
}

func TestLoggerHandlesConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer logger.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Log("concurrent", "test", "success", nil)
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	lines := splitLines(string(data))
	if len(lines) != 20 {
		t.Fatalf("got %d audit lines, want 20", len(lines))
	}
	for _, line := range lines {
		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid audit JSON line %q: %v", line, err)
		}
	}
}

func TestSplitLinesKeepsFinalLineWithoutTrailingNewline(t *testing.T) {
	lines := splitLines("a\nb\nc")
	if len(lines) != 3 || lines[0] != "a" || lines[1] != "b" || lines[2] != "c" {
		t.Fatalf("splitLines returned %#v", lines)
	}
}
