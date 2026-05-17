//go:build linux

package health

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	healthpb "github.com/ravenwire/ravenwire/sensor-agent/internal/health/proto"
	"google.golang.org/grpc"
)

type recordingHealthStream struct {
	grpc.ClientStream
	sent    []*healthpb.HealthReport
	sendErr error
}

func (s *recordingHealthStream) Send(report *healthpb.HealthReport) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, report)
	return nil
}

func (s *recordingHealthStream) Recv() (*healthpb.HealthAck, error) {
	return nil, io.EOF
}

func TestBufferReportWritesLengthPrefixedJSON(t *testing.T) {
	bufferPath := filepath.Join(t.TempDir(), "health-buffer.bin")
	client := &StreamClient{bufferPath: bufferPath, maxBufferBytes: 1024 * 1024}

	client.bufferReport(HealthReport{SensorPodID: "sensor-01", TimestampUnixMs: 123})

	data, err := os.ReadFile(bufferPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) < 5 {
		t.Fatalf("buffer too short: %d bytes", len(data))
	}

	length := int(binary.BigEndian.Uint32(data[:4]))
	if length != len(data)-4 {
		t.Fatalf("length prefix = %d, body len = %d", length, len(data)-4)
	}

	var report HealthReport
	if err := json.Unmarshal(data[4:], &report); err != nil {
		t.Fatalf("buffer body is not report JSON: %v", err)
	}
	if report.SensorPodID != "sensor-01" || report.TimestampUnixMs != 123 {
		t.Fatalf("buffered report = %#v", report)
	}
}

func TestReplayBufferSendsReportsAndClearsFile(t *testing.T) {
	bufferPath := filepath.Join(t.TempDir(), "health-buffer.bin")
	client := &StreamClient{bufferPath: bufferPath, maxBufferBytes: 1024 * 1024}
	client.bufferReport(HealthReport{SensorPodID: "sensor-01", TimestampUnixMs: 1})
	client.bufferReport(HealthReport{SensorPodID: "sensor-02", TimestampUnixMs: 2})

	stream := &recordingHealthStream{}
	if err := client.replayBuffer(stream); err != nil {
		t.Fatalf("replayBuffer: %v", err)
	}
	if len(stream.sent) != 2 {
		t.Fatalf("replayed %d reports, want 2", len(stream.sent))
	}
	if stream.sent[0].SensorPodId != "sensor-01" || stream.sent[1].SensorPodId != "sensor-02" {
		t.Fatalf("sent reports = %#v", stream.sent)
	}

	data, err := os.ReadFile(bufferPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("buffer should be cleared after replay, got %d bytes", len(data))
	}
}

func TestReplayBufferPreservesFileWhenSendFails(t *testing.T) {
	bufferPath := filepath.Join(t.TempDir(), "health-buffer.bin")
	client := &StreamClient{bufferPath: bufferPath, maxBufferBytes: 1024 * 1024}
	client.bufferReport(HealthReport{SensorPodID: "sensor-01", TimestampUnixMs: 1})

	stream := &recordingHealthStream{sendErr: errors.New("send failed")}
	if err := client.replayBuffer(stream); err == nil {
		t.Fatal("replayBuffer should return send error")
	}

	data, err := os.ReadFile(bufferPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("buffer should remain when replay send fails")
	}
}
