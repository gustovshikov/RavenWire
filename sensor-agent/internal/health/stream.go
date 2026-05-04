//go:build linux

package health

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"time"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
	healthpb "github.com/ravenwire/ravenwire/sensor-agent/internal/health/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// StreamClient manages the persistent bidirectional gRPC health stream to Config_Manager.
// On disconnect it buffers reports locally and replays them on reconnect.
// Reconnection uses exponential backoff (1s → 60s max).
type StreamClient struct {
	configManagerAddr string // host:port, e.g. "config-manager:9090"
	certDir           string
	bufferPath        string
	maxBufferBytes    int64
	collector         *Collector
	auditLog          *audit.Logger
}

// NewStreamClient creates a new StreamClient.
// configManagerAddr should be "host:port" (port 9090 per design).
func NewStreamClient(configManagerAddr, certDir, bufferPath string, collector *Collector, auditLog *audit.Logger) *StreamClient {
	return &StreamClient{
		configManagerAddr: configManagerAddr,
		certDir:           certDir,
		bufferPath:        bufferPath,
		maxBufferBytes:    100 * 1024 * 1024, // 100 MB default
		collector:         collector,
		auditLog:          auditLog,
	}
}

// Run starts the health streaming loop. Reconnects with exponential backoff on disconnect.
// Blocks until done is closed.
func (s *StreamClient) Run(done <-chan struct{}) {
	backoff := time.Second
	const maxBackoff = 60 * time.Second

	for {
		select {
		case <-done:
			return
		default:
		}

		log.Printf("health: connecting to Config_Manager at %s", s.configManagerAddr)
		err := s.stream(done)
		if err != nil {
			log.Printf("health: stream disconnected: %v; retrying in %v", err, backoff)
			select {
			case <-done:
				return
			case <-time.After(backoff):
			}
			backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
		} else {
			backoff = time.Second // reset on clean disconnect
		}
	}
}

// stream establishes a gRPC connection, replays any buffered reports, then
// streams live HealthReports until disconnect or done is closed.
func (s *StreamClient) stream(done <-chan struct{}) error {
	conn, err := s.dial()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	client := healthpb.NewHealthServiceClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancel the context when done is closed so the gRPC stream unblocks.
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()

	grpcStream, err := client.StreamHealth(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	// Drain acks in the background; log them but don't block sending.
	go s.drainAcks(grpcStream)

	// Replay buffered reports first.
	if err := s.replayBuffer(grpcStream); err != nil {
		log.Printf("health: buffer replay failed: %v", err)
	}

	// Stream live reports. The collector is scoped to this stream attempt so a
	// reconnect cannot leave behind a producer with no reader.
	reportCh := make(chan HealthReport, 16)
	collectorDone := make(chan struct{})
	defer close(collectorDone)
	go s.collector.Run(collectorDone, reportCh)

	for {
		select {
		case <-done:
			_ = grpcStream.CloseSend()
			return nil
		case report, ok := <-reportCh:
			if !ok {
				return fmt.Errorf("collector channel closed")
			}
			if err := grpcStream.Send(report.ToProto()); err != nil {
				s.bufferReport(report)
				return fmt.Errorf("send: %w", err)
			}
		}
	}
}

// dial creates a gRPC client connection with mTLS if certs are present,
// falling back to insecure transport for dev/enrollment-pending scenarios.
func (s *StreamClient) dial() (*grpc.ClientConn, error) {
	// Allow forcing insecure mode via env var (dev/demo deployments without server TLS)
	if os.Getenv("GRPC_INSECURE") == "true" {
		log.Printf("health: GRPC_INSECURE=true, connecting without TLS")
		return grpc.NewClient(s.configManagerAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}

	certFile := s.certDir + "/sensor.crt"
	keyFile := s.certDir + "/sensor.key"
	caFile := s.certDir + "/ca-chain.pem"

	if fileExists(certFile) && fileExists(keyFile) && fileExists(caFile) {
		tlsCfg, err := buildTLSConfig(certFile, keyFile, caFile)
		if err != nil {
			return nil, fmt.Errorf("build mTLS config: %w", err)
		}
		return grpc.NewClient(s.configManagerAddr,
			grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		)
	}

	log.Printf("health: certs not found at %s, connecting without mTLS", s.certDir)
	return grpc.NewClient(s.configManagerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

// buildTLSConfig constructs a tls.Config for mTLS using the cert/key/CA files.
func buildTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert/key: %w", err)
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert from %s", caFile)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// drainAcks reads HealthAck messages from the server stream and logs them.
// Runs until the stream closes.
func (s *StreamClient) drainAcks(stream healthpb.HealthService_StreamHealthClient) {
	for {
		ack, err := stream.Recv()
		if err != nil {
			if err != io.EOF {
				log.Printf("health: ack stream closed: %v", err)
			}
			return
		}
		log.Printf("health: ack from Config_Manager (pod=%s, ts=%d)",
			ack.GetSensorPodId(), ack.GetAckTimestampUnixMs())
	}
}

// bufferReport appends a HealthReport to the local ring buffer file using
// length-prefixed JSON records: [4-byte big-endian length][JSON data].
func (s *StreamClient) bufferReport(report HealthReport) {
	data, err := json.Marshal(report)
	if err != nil {
		log.Printf("health: failed to marshal report for buffer: %v", err)
		return
	}

	f, err := os.OpenFile(s.bufferPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("health: failed to open buffer file %s: %v", s.bufferPath, err)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err == nil && info.Size() >= s.maxBufferBytes {
		log.Printf("health: buffer file at max size (%d bytes), dropping report", s.maxBufferBytes)
		return
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := f.Write(lenBuf[:]); err != nil {
		log.Printf("health: buffer write length prefix: %v", err)
		return
	}
	if _, err := f.Write(data); err != nil {
		log.Printf("health: buffer write data: %v", err)
	}
}

// replayBuffer reads buffered reports and sends them over the provided gRPC stream.
// Clears the buffer file after a successful replay.
func (s *StreamClient) replayBuffer(stream healthpb.HealthService_StreamHealthClient) error {
	data, err := os.ReadFile(s.bufferPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read buffer %s: %w", s.bufferPath, err)
	}
	if len(data) == 0 {
		return nil
	}

	log.Printf("health: replaying %d bytes from buffer %s", len(data), s.bufferPath)

	offset := 0
	replayed := 0
	for offset+4 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if offset+length > len(data) {
			log.Printf("health: truncated record in buffer at offset %d, stopping replay", offset-4)
			break
		}

		var report HealthReport
		if err := json.Unmarshal(data[offset:offset+length], &report); err != nil {
			log.Printf("health: skipping malformed buffer record: %v", err)
			offset += length
			continue
		}
		offset += length

		if err := stream.Send(report.ToProto()); err != nil {
			return fmt.Errorf("replay send at record %d: %w", replayed, err)
		}
		replayed++
	}

	log.Printf("health: replayed %d buffered reports", replayed)
	return os.WriteFile(s.bufferPath, nil, 0640)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
