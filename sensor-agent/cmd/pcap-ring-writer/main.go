//go:build linux

// pcap_ring_writer — production AF_PACKET ring buffer writer.
//
// Upgraded from spike/pcap_ring_writer with:
//   - SO_TIMESTAMPNS for kernel-accurate packet timestamps
//   - RING_MAX_PACKETS configurable via env var
//   - Control socket authentication: restricted to sensor-svc UID only
//   - Proper Unix socket framing (length-prefixed JSON, no nc dependency)
//
// Environment variables:
//
//	CAPTURE_IFACE    — network interface to capture on (default: eth0)
//	RING_SIZE_MB     — size of the mmap ring in /dev/shm (default: 4096)
//	RING_MAX_PACKETS — maximum packet slots in the ring index (default: 1048576)
//	CONTROL_SOCK     — path to Unix socket (default: /var/run/pcap_ring.sock)
//	RING_PATH        — path to ring file (default: /dev/shm/sensor_pcap_ring)
//	SENSOR_SVC_UID   — UID allowed to connect to control socket (default: 10000)
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// ── PCAP file format constants ────────────────────────────────────────────────

const (
	pcapMagicNumber  = 0xa1b2c3d4
	pcapVersionMajor = 2
	pcapVersionMinor = 4
	pcapLinkTypeEth  = 1
	pcapSnapLen      = 65535
)

type pcapGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	Thiszone     int32
	Sigfigs      uint32
	Snaplen      uint32
	Network      uint32
}

type pcapPacketHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// ── Ring buffer ───────────────────────────────────────────────────────────────

type packetRecord struct {
	TimestampNs int64  // Unix nanoseconds (SO_TIMESTAMPNS)
	CapLen      uint32
	OrigLen     uint32
	Offset      uint64
}

const recordHeaderSize = int(unsafe.Sizeof(packetRecord{}))

// Ring holds the memory-mapped ring state.
type Ring struct {
	mu sync.RWMutex

	data            []byte
	ringSize        int64
	indexRegionSize int64
	dataRegionSize  int64
	maxPackets      int

	writeHead    uint64
	dataWriteOff uint64

	packetsWritten uint64
	bytesWritten   uint64
	wrapCount      uint64
}

func newRing(path string, sizeMB, maxPkts int) (*Ring, error) {
	size := int64(sizeMB) * 1024 * 1024

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("open ring file: %w", err)
	}
	defer f.Close()

	if err := f.Truncate(size); err != nil {
		return nil, fmt.Errorf("truncate ring file: %w", err)
	}

	data, err := syscall.Mmap(int(f.Fd()), 0, int(size),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap ring: %w", err)
	}

	indexRegionSize := int64(maxPkts * recordHeaderSize)
	if indexRegionSize >= size {
		return nil, fmt.Errorf("ring too small for index region (%d bytes needed)", indexRegionSize)
	}

	return &Ring{
		data:            data,
		ringSize:        size,
		indexRegionSize: indexRegionSize,
		dataRegionSize:  size - indexRegionSize,
		maxPackets:      maxPkts,
	}, nil
}

func (r *Ring) writePacket(tsNs int64, pkt []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	capLen := uint32(len(pkt))
	if int64(capLen) > r.dataRegionSize {
		capLen = uint32(r.dataRegionSize)
	}

	dataOff := r.dataWriteOff % uint64(r.dataRegionSize)
	dataStart := uint64(r.indexRegionSize) + dataOff

	remaining := uint64(r.dataRegionSize) - dataOff
	if uint64(capLen) > remaining {
		for i := dataStart; i < uint64(r.indexRegionSize)+uint64(r.dataRegionSize); i++ {
			r.data[i] = 0
		}
		dataOff = 0
		dataStart = uint64(r.indexRegionSize)
		atomic.AddUint64(&r.wrapCount, 1)
	}

	copy(r.data[dataStart:dataStart+uint64(capLen)], pkt[:capLen])

	slot := r.writeHead % uint64(r.maxPackets)
	rec := packetRecord{
		TimestampNs: tsNs,
		CapLen:      capLen,
		OrigLen:     uint32(len(pkt)),
		Offset:      dataOff,
	}
	recBytes := (*[recordHeaderSize]byte)(unsafe.Pointer(&rec))[:]
	copy(r.data[slot*uint64(recordHeaderSize):], recBytes)

	r.writeHead++
	r.dataWriteOff = dataOff + uint64(capLen)
	r.packetsWritten++
	r.bytesWritten += uint64(capLen)
}

func (r *Ring) carveWindow(preAlertNs, postAlertNs int64, outputPath string) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	f, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("create output pcap: %w", err)
	}
	defer f.Close()

	gh := pcapGlobalHeader{
		MagicNumber:  pcapMagicNumber,
		VersionMajor: pcapVersionMajor,
		VersionMinor: pcapVersionMinor,
		Snaplen:      pcapSnapLen,
		Network:      pcapLinkTypeEth,
	}
	if err := binary.Write(f, binary.LittleEndian, gh); err != nil {
		return 0, err
	}

	count := 0
	total := r.writeHead
	if total > uint64(r.maxPackets) {
		total = uint64(r.maxPackets)
	}

	startSlot := uint64(0)
	if r.writeHead > uint64(r.maxPackets) {
		startSlot = r.writeHead % uint64(r.maxPackets)
	}

	for i := uint64(0); i < total; i++ {
		slot := (startSlot + i) % uint64(r.maxPackets)
		recBytes := r.data[slot*uint64(recordHeaderSize) : (slot+1)*uint64(recordHeaderSize)]
		rec := *(*packetRecord)(unsafe.Pointer(&recBytes[0]))

		if rec.TimestampNs < preAlertNs || rec.TimestampNs > postAlertNs {
			continue
		}
		if rec.CapLen == 0 {
			continue
		}

		dataStart := uint64(r.indexRegionSize) + rec.Offset
		if dataStart+uint64(rec.CapLen) > uint64(r.ringSize) {
			continue
		}
		pktData := r.data[dataStart : dataStart+uint64(rec.CapLen)]

		tsSec := uint32(rec.TimestampNs / 1e9)
		tsUsec := uint32((rec.TimestampNs % 1e9) / 1000)

		ph := pcapPacketHeader{
			TsSec:   tsSec,
			TsUsec:  tsUsec,
			InclLen: rec.CapLen,
			OrigLen: rec.OrigLen,
		}
		if err := binary.Write(f, binary.LittleEndian, ph); err != nil {
			return count, err
		}
		if _, err := f.Write(pktData); err != nil {
			return count, err
		}
		count++
	}

	return count, nil
}

func (r *Ring) stats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return map[string]interface{}{
		"packets_written": r.packetsWritten,
		"bytes_written":   r.bytesWritten,
		"wrap_count":      r.wrapCount,
		"write_head":      r.writeHead,
	}
}

// ── AF_PACKET capture with SO_TIMESTAMPNS ─────────────────────────────────────

func startCapture(iface string, ring *Ring, done <-chan struct{}) error {
	const ethPAll = 0x0003

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}

	// Enable SO_TIMESTAMPNS for kernel-accurate nanosecond timestamps
	if err := setSockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
		log.Printf("pcap_ring_writer: SO_TIMESTAMPNS not available, using userspace time: %v", err)
	}

	ifIndex, err := getIfIndex(fd, iface)
	if err != nil {
		syscall.Close(fd)
		return fmt.Errorf("get interface index: %w", err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  ifIndex,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("bind: %w", err)
	}

	// Join PACKET_FANOUT group 4 (PACKET_FANOUT_HASH = 0)
	const packetFanoutHash = 0
	fanoutArg := uint32(4) | (packetFanoutHash << 16)
	if err := setSockoptInt(fd, syscall.SOL_PACKET, 18 /* PACKET_FANOUT */, int(fanoutArg)); err != nil {
		log.Printf("pcap_ring_writer: PACKET_FANOUT join (group 4): %v", err)
	}

	log.Printf("pcap_ring_writer: AF_PACKET socket bound on %s (fanout group 4)", iface)

	go func() {
		defer syscall.Close(fd)
		buf := make([]byte, 65536)
		oob := make([]byte, 1024) // for SO_TIMESTAMPNS cmsg

		for {
			select {
			case <-done:
				return
			default:
			}

			tv := syscall.Timeval{Sec: 0, Usec: 100000}
			syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

			n, oobn, _, _, err := syscall.Recvmsg(fd, buf, oob, 0)
			if err != nil {
				if isTimeout(err) {
					continue
				}
				log.Printf("pcap_ring_writer: recvmsg: %v", err)
				continue
			}

			// Extract kernel timestamp from SO_TIMESTAMPNS cmsg
			tsNs := extractTimestampNs(oob[:oobn])
			if tsNs == 0 {
				tsNs = time.Now().UnixNano()
			}

			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			ring.writePacket(tsNs, pkt)
		}
	}()

	return nil
}

// extractTimestampNs extracts a SO_TIMESTAMPNS timestamp from a cmsg buffer.
func extractTimestampNs(oob []byte) int64 {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_SOCKET && msg.Header.Type == syscall.SO_TIMESTAMPNS {
			if len(msg.Data) >= 16 {
				sec := int64(binary.LittleEndian.Uint64(msg.Data[0:8]))
				nsec := int64(binary.LittleEndian.Uint64(msg.Data[8:16]))
				return sec*1e9 + nsec
			}
		}
	}
	return 0
}

// ── Control socket ────────────────────────────────────────────────────────────

type controlCmd struct {
	Cmd         string `json:"cmd"`
	TimestampMs int64  `json:"timestamp_ms,omitempty"`
	PreAlertNs  int64  `json:"pre_alert_ns,omitempty"`
	PostAlertNs int64  `json:"post_alert_ns,omitempty"`
	OutputPath  string `json:"output_path,omitempty"`
	BPFFilter   string `json:"bpf_filter,omitempty"`
}

type controlResp struct {
	Status      string                 `json:"status"`
	Error       string                 `json:"error,omitempty"`
	PacketCount int                    `json:"packet_count,omitempty"`
	OutputPath  string                 `json:"output_path,omitempty"`
	Stats       map[string]interface{} `json:"stats,omitempty"`
}

func serveControl(sockPath string, ring *Ring, preAlertMark *int64, allowedUID int) error {
	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", sockPath, err)
	}

	// Restrict socket permissions to owner only
	if err := os.Chmod(sockPath, 0600); err != nil {
		log.Printf("pcap_ring_writer: chmod control socket: %v", err)
	}

	log.Printf("pcap_ring_writer: control socket at %s (allowed UID: %d)", sockPath, allowedUID)

	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			// Authenticate: check peer UID via SO_PEERCRED
			if !authenticateConn(conn, allowedUID) {
				log.Printf("pcap_ring_writer: rejected connection from unauthorized UID")
				conn.Close()
				continue
			}

			go handleControl(conn, ring, preAlertMark)
		}
	}()
	return nil
}

// authenticateConn checks that the connecting process has the allowed UID.
func authenticateConn(conn net.Conn, allowedUID int) bool {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}

	var cred *syscall.Ucred
	var credErr error
	rawConn.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})

	if credErr != nil || cred == nil {
		return false
	}

	// Allow root (UID 0) and the configured sensor-svc UID
	return int(cred.Uid) == 0 || int(cred.Uid) == allowedUID
}

func handleControl(conn net.Conn, ring *Ring, preAlertMark *int64) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	var cmd controlCmd
	if err := dec.Decode(&cmd); err != nil {
		enc.Encode(controlResp{Status: "error", Error: err.Error()})
		return
	}

	switch cmd.Cmd {
	case "status":
		enc.Encode(controlResp{Status: "ok", Stats: ring.stats()})

	case "mark_pre_alert":
		tsNs := cmd.TimestampMs * int64(time.Millisecond)
		atomic.StoreInt64(preAlertMark, tsNs)
		log.Printf("pcap_ring_writer: pre-alert mark set: %d ns", tsNs)
		enc.Encode(controlResp{Status: "ok"})

	case "carve_window":
		if cmd.OutputPath == "" {
			enc.Encode(controlResp{Status: "error", Error: "output_path required"})
			return
		}
		count, err := ring.carveWindow(cmd.PreAlertNs, cmd.PostAlertNs, cmd.OutputPath)
		if err != nil {
			enc.Encode(controlResp{Status: "error", Error: err.Error()})
			return
		}
		log.Printf("pcap_ring_writer: carved %d packets to %s", count, cmd.OutputPath)
		enc.Encode(controlResp{Status: "ok", PacketCount: count, OutputPath: cmd.OutputPath})

	case "configure":
		log.Printf("pcap_ring_writer: BPF filter update: %q", cmd.BPFFilter)
		// TODO: reattach SO_ATTACH_FILTER to the AF_PACKET socket
		enc.Encode(controlResp{Status: "ok"})

	default:
		enc.Encode(controlResp{Status: "error", Error: "unknown command: " + cmd.Cmd})
	}
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	iface := envOrDefault("CAPTURE_IFACE", "eth0")
	ringPath := envOrDefault("RING_PATH", "/dev/shm/sensor_pcap_ring")
	controlSock := envOrDefault("CONTROL_SOCK", "/var/run/pcap_ring.sock")
	ringSizeMB := envIntOrDefault("RING_SIZE_MB", 4096)
	maxPackets := envIntOrDefault("RING_MAX_PACKETS", 1<<20)
	allowedUID := envIntOrDefault("SENSOR_SVC_UID", 10000)

	log.Printf("pcap_ring_writer: starting iface=%s ring=%s size=%dMB max_packets=%d ctrl=%s",
		iface, ringPath, ringSizeMB, maxPackets, controlSock)

	ring, err := newRing(ringPath, ringSizeMB, maxPackets)
	if err != nil {
		log.Fatalf("pcap_ring_writer: init ring: %v", err)
	}
	log.Printf("pcap_ring_writer: ring initialized %dMB at %s", ringSizeMB, ringPath)

	var preAlertMark int64

	if err := serveControl(controlSock, ring, &preAlertMark, allowedUID); err != nil {
		log.Fatalf("pcap_ring_writer: control socket: %v", err)
	}

	done := make(chan struct{})
	if err := startCapture(iface, ring, done); err != nil {
		log.Fatalf("pcap_ring_writer: start capture: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("pcap_ring_writer: shutting down")
	close(done)

	stats := ring.stats()
	log.Printf("pcap_ring_writer: final stats: packets=%v bytes=%v wraps=%v",
		stats["packets_written"], stats["bytes_written"], stats["wrap_count"])
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func htons(v uint16) uint16 { return (v>>8)&0xff | (v&0xff)<<8 }

func isTimeout(err error) bool {
	if errno, ok := err.(syscall.Errno); ok {
		return errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK
	}
	return false
}

func getIfIndex(fd int, iface string) (int, error) {
	type ifreqIndex struct {
		Name  [16]byte
		Index int32
		_     [20]byte
	}
	var req ifreqIndex
	copy(req.Name[:], iface)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		syscall.SIOCGIFINDEX, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return 0, errno
	}
	return int(req.Index), nil
}

func setSockoptInt(fd, level, opt, value int) error {
	v := int32(value)
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(unsafe.Pointer(&v)), 4, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
