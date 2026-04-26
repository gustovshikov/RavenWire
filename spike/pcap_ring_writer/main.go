// pcap_ring_writer — AF_PACKET ring buffer writer with Unix socket control interface.
//
// Spike implementation: validates that a dedicated process can bind AF_PACKET with
// fanout group 4, write packets to a memory-mapped ring in /dev/shm, and serve
// carve requests over a Unix socket control interface.
//
// Environment variables:
//   CAPTURE_IFACE   — network interface to capture on (default: eth0)
//   RING_SIZE_MB    — size of the mmap ring in /dev/shm (default: 512)
//   CONTROL_SOCK    — path to Unix socket (default: /var/run/pcap_ring.sock)
//   RING_PATH       — path to ring file (default: /dev/shm/sensor_pcap_ring)
//
// Control commands (newline-delimited JSON on the Unix socket):
//   {"cmd":"status"}
//   {"cmd":"mark_pre_alert","timestamp_ms":<unix_ms>}
//   {"cmd":"carve_window","pre_alert_ms":<unix_ms>,"post_alert_ms":<unix_ms>,"output_path":"<path>"}
//   {"cmd":"configure","bpf_filter":"<filter_string>"}

//go:build linux

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

// pcapGlobalHeader is the 24-byte libpcap global header.
type pcapGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	Thiszone     int32
	Sigfigs      uint32
	Snaplen      uint32
	Network      uint32
}

// pcapPacketHeader is the 16-byte per-packet header.
type pcapPacketHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// ── Ring buffer ───────────────────────────────────────────────────────────────

// packetRecord is stored in the ring for each captured packet.
// Fixed-size header followed by variable-length data stored separately.
type packetRecord struct {
	TimestampMs int64  // Unix milliseconds
	CapLen      uint32 // captured length
	OrigLen     uint32 // original length
	Offset      uint64 // byte offset into the data region of the ring
}

const (
	recordHeaderSize = int(unsafe.Sizeof(packetRecord{}))
	// Ring layout: [index region][data region]
	// index region: maxPackets * recordHeaderSize
	// data region: remainder
	maxPackets = 1 << 20 // 1M packet slots
)

// Ring holds the memory-mapped ring state.
type Ring struct {
	mu sync.RWMutex

	data     []byte // mmap'd region
	ringSize int64  // total size in bytes

	indexRegionSize int64 // maxPackets * recordHeaderSize
	dataRegionSize  int64 // ringSize - indexRegionSize

	writeHead   uint64 // next packet slot index (wraps at maxPackets)
	dataWriteOff uint64 // next byte offset in data region (wraps at dataRegionSize)

	packetsWritten uint64
	bytesWritten   uint64
	wrapCount      uint64
}

func newRing(path string, sizeMB int) (*Ring, error) {
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

	indexRegionSize := int64(maxPackets * recordHeaderSize)
	if indexRegionSize >= size {
		return nil, fmt.Errorf("ring too small for index region (%d bytes needed)", indexRegionSize)
	}

	return &Ring{
		data:            data,
		ringSize:        size,
		indexRegionSize: indexRegionSize,
		dataRegionSize:  size - indexRegionSize,
	}, nil
}

// writePacket appends a packet to the ring. Thread-safe.
func (r *Ring) writePacket(tsMs int64, pkt []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	capLen := uint32(len(pkt))
	if int64(capLen) > r.dataRegionSize {
		capLen = uint32(r.dataRegionSize)
	}

	// Write packet data into data region (wrapping)
	dataOff := r.dataWriteOff % uint64(r.dataRegionSize)
	dataStart := uint64(r.indexRegionSize) + dataOff

	// Handle wrap: if packet doesn't fit at end, wrap to beginning
	remaining := uint64(r.dataRegionSize) - dataOff
	if uint64(capLen) > remaining {
		// Zero-fill the gap and wrap
		for i := dataStart; i < uint64(r.indexRegionSize)+uint64(r.dataRegionSize); i++ {
			r.data[i] = 0
		}
		dataOff = 0
		dataStart = uint64(r.indexRegionSize)
		atomic.AddUint64(&r.wrapCount, 1)
	}

	copy(r.data[dataStart:dataStart+uint64(capLen)], pkt[:capLen])

	// Write index record
	slot := r.writeHead % uint64(maxPackets)
	rec := packetRecord{
		TimestampMs: tsMs,
		CapLen:      capLen,
		OrigLen:     uint32(len(pkt)),
		Offset:      dataOff,
	}
	recBytes := (*[recordHeaderSize]byte)(unsafe.Pointer(&rec))[:]
	copy(r.data[slot*uint64(recordHeaderSize):], recBytes)

	r.writeHead++
	// Update absolute data write offset; carveWindow uses rec.Offset (the modulo value)
	// so we track the absolute value here and compute modulo at the top of each call.
	r.dataWriteOff = dataOff + uint64(capLen)
	r.packetsWritten++
	r.bytesWritten += uint64(capLen)
}

// carveWindow extracts packets in [preAlertMs, postAlertMs] and writes a PCAP file.
func (r *Ring) carveWindow(preAlertMs, postAlertMs int64, outputPath string) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	f, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("create output pcap: %w", err)
	}
	defer f.Close()

	// Write global PCAP header
	gh := pcapGlobalHeader{
		MagicNumber:  pcapMagicNumber,
		VersionMajor: pcapVersionMajor,
		VersionMinor: pcapVersionMinor,
		Thiszone:     0,
		Sigfigs:      0,
		Snaplen:      pcapSnapLen,
		Network:      pcapLinkTypeEth,
	}
	if err := binary.Write(f, binary.LittleEndian, gh); err != nil {
		return 0, fmt.Errorf("write pcap global header: %w", err)
	}

	count := 0
	total := r.writeHead
	if total > uint64(maxPackets) {
		total = uint64(maxPackets)
	}

	// Iterate over all valid slots in write order
	startSlot := uint64(0)
	if r.writeHead > uint64(maxPackets) {
		startSlot = r.writeHead % uint64(maxPackets)
	}

	for i := uint64(0); i < total; i++ {
		slot := (startSlot + i) % uint64(maxPackets)
		recBytes := r.data[slot*uint64(recordHeaderSize) : (slot+1)*uint64(recordHeaderSize)]
		rec := *(*packetRecord)(unsafe.Pointer(&recBytes[0]))

		if rec.TimestampMs < preAlertMs || rec.TimestampMs > postAlertMs {
			continue
		}
		if rec.CapLen == 0 {
			continue
		}

		// Read packet data from data region
		dataStart := uint64(r.indexRegionSize) + rec.Offset
		if dataStart+uint64(rec.CapLen) > uint64(r.ringSize) {
			continue // corrupted or wrapped-over record
		}
		pktData := r.data[dataStart : dataStart+uint64(rec.CapLen)]

		tsSec := uint32(rec.TimestampMs / 1000)
		tsUsec := uint32((rec.TimestampMs % 1000) * 1000)

		ph := pcapPacketHeader{
			TsSec:   tsSec,
			TsUsec:  tsUsec,
			InclLen: rec.CapLen,
			OrigLen: rec.OrigLen,
		}
		if err := binary.Write(f, binary.LittleEndian, ph); err != nil {
			return count, fmt.Errorf("write packet header: %w", err)
		}
		if _, err := f.Write(pktData); err != nil {
			return count, fmt.Errorf("write packet data: %w", err)
		}
		count++
	}

	return count, nil
}

// stats returns a snapshot of ring statistics.
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

// ── AF_PACKET capture ─────────────────────────────────────────────────────────

// startCapture binds an AF_PACKET socket on iface with fanout group 4 and
// feeds packets into the ring. Runs until ctx is cancelled.
func startCapture(iface string, ring *Ring, bpfFilter *string, done <-chan struct{}) error {
	// ETH_P_ALL = 0x0003 (capture all Ethernet frames), big-endian
	const ethPAll = 0x0003

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW,
		int(htons(ethPAll)))
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}

	// Bind to the interface
	ifreq, err := getIfIndex(fd, iface)
	if err != nil {
		syscall.Close(fd)
		return fmt.Errorf("get interface index: %w", err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  ifreq,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("bind: %w", err)
	}

	// Join PACKET_FANOUT group 4 (PACKET_FANOUT_HASH = 0)
	// fanout_arg = (group_id & 0xffff) | (fanout_type << 16)
	const packetFanoutHash = 0
	fanoutArg := uint32(4) | (packetFanoutHash << 16)
	if err := setSockoptInt(fd, syscall.SOL_PACKET, 18 /* PACKET_FANOUT */, int(fanoutArg)); err != nil {
		// Non-fatal in spike: fanout requires multiple sockets in same group
		log.Printf("PACKET_FANOUT join (group 4): %v (may need multiple sockets)", err)
	}

	log.Printf("AF_PACKET socket bound on %s (fanout group 4)", iface)

	go func() {
		defer syscall.Close(fd)
		buf := make([]byte, 65536)
		for {
			select {
			case <-done:
				return
			default:
			}

			// Set a short read deadline so we can check done channel
			tv := syscall.Timeval{Sec: 0, Usec: 100000} // 100ms
			syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if isTimeout(err) {
					continue
				}
				log.Printf("recvfrom: %v", err)
				continue
			}

			tsMs := time.Now().UnixMilli()
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			ring.writePacket(tsMs, pkt)
		}
	}()

	return nil
}

func htons(v uint16) uint16 {
	return (v>>8)&0xff | (v&0xff)<<8
}

func isTimeout(err error) bool {
	if errno, ok := err.(syscall.Errno); ok {
		return errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK
	}
	return false
}

func getIfIndex(fd int, iface string) (int, error) {
	// Use SIOCGIFINDEX ioctl
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

// ── Control socket ────────────────────────────────────────────────────────────

type controlCmd struct {
	Cmd         string `json:"cmd"`
	TimestampMs int64  `json:"timestamp_ms,omitempty"`
	PreAlertMs  int64  `json:"pre_alert_ms,omitempty"`
	PostAlertMs int64  `json:"post_alert_ms,omitempty"`
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

func serveControl(sockPath string, ring *Ring, preAlertMark *int64) error {
	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", sockPath, err)
	}
	log.Printf("Control socket listening at %s", sockPath)

	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("control accept: %v", err)
				return
			}
			go handleControl(conn, ring, preAlertMark)
		}
	}()
	return nil
}

func handleControl(conn net.Conn, ring *Ring, preAlertMark *int64) {
	defer conn.Close()

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
		atomic.StoreInt64(preAlertMark, cmd.TimestampMs)
		log.Printf("Pre-alert mark set: %d ms", cmd.TimestampMs)
		enc.Encode(controlResp{Status: "ok"})

	case "carve_window":
		if cmd.OutputPath == "" {
			enc.Encode(controlResp{Status: "error", Error: "output_path required"})
			return
		}
		count, err := ring.carveWindow(cmd.PreAlertMs, cmd.PostAlertMs, cmd.OutputPath)
		if err != nil {
			enc.Encode(controlResp{Status: "error", Error: err.Error()})
			return
		}
		log.Printf("Carved %d packets to %s", count, cmd.OutputPath)
		enc.Encode(controlResp{Status: "ok", PacketCount: count, OutputPath: cmd.OutputPath})

	case "configure":
		// In the spike we just log the new BPF filter; full implementation
		// would reattach SO_ATTACH_FILTER to the AF_PACKET socket.
		log.Printf("BPF filter update: %q", cmd.BPFFilter)
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
	ringSizeMB := envIntOrDefault("RING_SIZE_MB", 512)

	log.Printf("pcap_ring_writer starting: iface=%s ring=%s size=%dMB ctrl=%s",
		iface, ringPath, ringSizeMB, controlSock)

	ring, err := newRing(ringPath, ringSizeMB)
	if err != nil {
		log.Fatalf("init ring: %v", err)
	}
	log.Printf("Ring initialized: %d MB at %s", ringSizeMB, ringPath)

	var preAlertMark int64

	if err := serveControl(controlSock, ring, &preAlertMark); err != nil {
		log.Fatalf("control socket: %v", err)
	}

	done := make(chan struct{})
	if err := startCapture(iface, ring, nil, done); err != nil {
		log.Fatalf("start capture: %v", err)
	}

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	close(done)

	stats := ring.stats()
	log.Printf("Final stats: packets=%v bytes=%v wraps=%v",
		stats["packets_written"], stats["bytes_written"], stats["wrap_count"])
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
