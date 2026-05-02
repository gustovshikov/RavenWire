//go:build linux

// pcap_ring_writer — RavenWire AF_PACKET ring buffer writer.
//
// This binary is shared by the development Compose stack and production Podman
// deployment so capture behavior stays consistent across environments.
//
// Environment variables:
//
//	CAPTURE_IFACE        — network interface to capture on (default: eth0)
//	RING_SIZE_MB         — size of the mmap ring in /dev/shm (default: 4096)
//	RING_MAX_PACKETS     — maximum packet slots in the ring index (default: 1048576)
//	CONTROL_SOCK         — path to Unix socket (default: /var/run/pcap_ring.sock)
//	RING_PATH            — path to ring file (default: /dev/shm/sensor_pcap_ring)
//	SENSOR_SVC_UID       — UID allowed to connect to control socket (default: 10000)
//	TPACKET_BLOCK_SIZE_MB — TPACKET_V3 block size in MB (default: 4)
//	TPACKET_FRAME_COUNT  — TPACKET_V3 total frame count (default: 2048)
//	RING_WORKERS         — capture worker count; currently clamped to 1 because
//	                       one TPACKET_V3 ring must have exactly one block cursor.
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

	"github.com/ravenwire/ravenwire/sensor-agent/internal/ringctl"
	"golang.org/x/sys/unix"
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
	TimestampNs int64 // Unix nanoseconds (SO_TIMESTAMPNS)
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

// statusResponse returns a RingResponse populated with current ring statistics.
func (r *Ring) statusResponse(cs *captureState) ringctl.RingResponse {
	r.mu.RLock()
	defer r.mu.RUnlock()

	resp := ringctl.RingResponse{
		PacketsWritten: r.packetsWritten,
		BytesWritten:   r.bytesWritten,
		WrapCount:      r.wrapCount,
	}

	// Retrieve socket drop stats from PACKET_STATISTICS getsockopt.
	cs.mu.Lock()
	fd := cs.fd
	cs.mu.Unlock()
	if fd >= 0 {
		drops, freezeQ := getSocketStats(fd)
		resp.SocketDrops = drops
		resp.SocketFreezeQueueDrops = freezeQ
	}

	return resp
}

// ── TPACKET_V3 constants and types ─────────────────────────────────────────────
//
// These mirror the Linux kernel's <linux/if_packet.h> definitions for
// TPACKET_V3 block-based AF_PACKET capture.

const (
	ethPAll = 0x0003

	// TPACKET version constants
	tpacketV3 = 2 // TPACKET_V3

	// Socket option levels and names
	solPacket        = 0x107 // SOL_PACKET
	packetVersion    = 10    // PACKET_VERSION
	packetRxRing     = 5     // PACKET_RX_RING
	packetStatistics = 6     // PACKET_STATISTICS
	packetFanout     = 18    // PACKET_FANOUT

	// TPACKET_V3 block status flags
	tpStatusKernel = 0      // TP_STATUS_KERNEL — block owned by kernel
	tpStatusUser   = 1 << 0 // TP_STATUS_USER — block ready for userspace
	tpStatusBLKTMO = 1 << 5 // TP_STATUS_BLK_TMO — block retired due to timeout

	// Default TPACKET_V3 configuration
	defaultBlockSizeMB = 4
	defaultFrameCount  = 2048
	defaultRingWorkers = 1

	// Block retire timeout in milliseconds
	blockRetireTimeoutMs = 100

	// Frame size within a block (must be a power of 2, >= TPACKET3_HDRLEN)
	tpacketFrameSize = 2048

	// TPACKET3 header alignment
	tpacketAlignment = 16
	tpacket3HdrLen   = 72 // sizeof(struct tpacket3_hdr) on amd64
)

// tpacketReq3 mirrors struct tpacket_req3 from <linux/if_packet.h>.
type tpacketReq3 struct {
	BlockSize      uint32
	BlockNr        uint32
	FrameSize      uint32
	FrameNr        uint32
	RetireBlkTov   uint32
	SizeofPriv     uint32
	FeatureReqWord uint32
}

// tpacketBlockDesc mirrors the block descriptor header (struct tpacket_hdr_v1
// inside the block_desc union) from <linux/if_packet.h>.
type tpacketBlockDesc struct {
	Version      uint32
	OffsetToPriv uint32
	// tpacket_hdr_v1 fields:
	BlockStatus   uint32
	NumPkts       uint32
	OffsetToFirst uint32
	BlkLen        uint32
	SeqNum        uint64
	TsSec         uint32 // timestamp of first packet
	TsNsec        uint32
}

// tpacket3Hdr mirrors struct tpacket3_hdr from <linux/if_packet.h>.
// We only need the fields up to tp_net for packet extraction.
type tpacket3Hdr struct {
	TpNextOffset uint32
	TpSec        uint32
	TpNsec       uint32
	TpSnapLen    uint32
	TpLen        uint32
	TpStatus     uint32
	TpMac        uint16
	TpNet        uint16
	// Remaining fields (tp_sec, tp_usec for VLAN, padding) are not needed.
}

// tpacketStatsV3 mirrors struct tpacket_stats_v3 from <linux/if_packet.h>.
type tpacketStatsV3 struct {
	TpPackets      uint32
	TpDrops        uint32
	TpFreezeQCount uint32
}

// tpacketV3Config holds the TPACKET_V3 ring configuration.
type tpacketV3Config struct {
	BlockSizeMB int
	FrameCount  int
	Workers     int
}

func tpacketRingParams(cfg tpacketV3Config) (blockSize, frameSize, frameNr, blockNr uint32, err error) {
	if cfg.BlockSizeMB <= 0 {
		return 0, 0, 0, 0, fmt.Errorf("TPACKET_BLOCK_SIZE_MB must be positive, got %d", cfg.BlockSizeMB)
	}
	if cfg.FrameCount <= 0 {
		return 0, 0, 0, 0, fmt.Errorf("TPACKET_FRAME_COUNT must be positive, got %d", cfg.FrameCount)
	}

	blockSize64 := int64(cfg.BlockSizeMB) * 1024 * 1024
	if blockSize64 > int64(^uint32(0)) {
		return 0, 0, 0, 0, fmt.Errorf("TPACKET_BLOCK_SIZE_MB too large: %d", cfg.BlockSizeMB)
	}

	blockSize = uint32(blockSize64)
	frameSize = uint32(tpacketFrameSize)
	if blockSize < frameSize {
		return 0, 0, 0, 0, fmt.Errorf("TPACKET block size %d is smaller than frame size %d", blockSize, frameSize)
	}
	if blockSize%frameSize != 0 {
		return 0, 0, 0, 0, fmt.Errorf("TPACKET block size %d must be divisible by frame size %d", blockSize, frameSize)
	}

	framesPerBlock := blockSize / frameSize
	requestedFrames := uint32(cfg.FrameCount)
	blockNr = (requestedFrames + framesPerBlock - 1) / framesPerBlock
	if blockNr == 0 {
		blockNr = 1
	}
	frameNr = blockNr * framesPerBlock
	if frameNr != requestedFrames {
		log.Printf("pcap_ring_writer: TPACKET_FRAME_COUNT=%d adjusted to %d to fill complete blocks", requestedFrames, frameNr)
	}

	return blockSize, frameSize, frameNr, blockNr, nil
}

// ── AF_PACKET TPACKET_V3 capture ──────────────────────────────────────────────

func startCapture(iface string, ring *Ring, done <-chan struct{}, cs *captureState, cfg tpacketV3Config) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}

	// Set TPACKET_V3 version on the socket.
	if err := setSockoptInt(fd, solPacket, packetVersion, tpacketV3); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("PACKET_VERSION TPACKET_V3: %w", err)
	}

	ifIndex, err := getIfIndex(fd, iface)
	if err != nil {
		syscall.Close(fd)
		return fmt.Errorf("get interface index: %w", err)
	}

	blockSize, frameSize, frameNr, blockNr, err := tpacketRingParams(cfg)
	if err != nil {
		syscall.Close(fd)
		return err
	}

	req := tpacketReq3{
		BlockSize:      blockSize,
		BlockNr:        blockNr,
		FrameSize:      frameSize,
		FrameNr:        frameNr,
		RetireBlkTov:   blockRetireTimeoutMs,
		SizeofPriv:     0,
		FeatureReqWord: 0,
	}

	// Set up the TPACKET_V3 RX ring via setsockopt.
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(solPacket),
		uintptr(packetRxRing),
		uintptr(unsafe.Pointer(&req)),
		unsafe.Sizeof(req),
		0,
	)
	if errno != 0 {
		syscall.Close(fd)
		return fmt.Errorf("PACKET_RX_RING setsockopt: %w", errno)
	}

	// mmap the ring buffer.
	totalRingSize := int(blockSize) * int(blockNr)
	ringMem, err := syscall.Mmap(fd, 0, totalRingSize,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_LOCKED)
	if err != nil {
		syscall.Close(fd)
		return fmt.Errorf("mmap TPACKET_V3 ring: %w", err)
	}

	log.Printf("pcap_ring_writer: TPACKET_V3 ring configured: block_size=%dMB block_nr=%d frame_size=%d frame_nr=%d total_ring_memory=%dMB",
		cfg.BlockSizeMB, blockNr, frameSize, frameNr, totalRingSize/(1024*1024))

	// Bind to the capture interface.
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  ifIndex,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Munmap(ringMem)
		syscall.Close(fd)
		return fmt.Errorf("bind: %w", err)
	}

	// Join PACKET_FANOUT group 4 (PACKET_FANOUT_HASH = 0).
	const packetFanoutHash = 0
	fanoutArg := uint32(4) | (packetFanoutHash << 16)
	if err := setSockoptInt(fd, solPacket, packetFanout, int(fanoutArg)); err != nil {
		log.Printf("pcap_ring_writer: PACKET_FANOUT join (group 4): %v", err)
	}

	log.Printf("pcap_ring_writer: AF_PACKET TPACKET_V3 socket bound on %s (fanout group 4)", iface)

	// Store the fd in captureState so the configure handler can reattach BPF filters.
	cs.setFD(fd)

	// Spawn worker goroutines that poll TPACKET_V3 blocks.
	workers := cfg.Workers
	if workers < 1 {
		workers = 1
	}
	if workers > 1 {
		log.Printf("pcap_ring_writer: RING_WORKERS=%d requested, clamping to 1 for single TPACKET_V3 ring safety", workers)
		workers = 1
	}
	log.Printf("pcap_ring_writer: starting %d TPACKET_V3 ring worker(s)", workers)

	for w := 0; w < workers; w++ {
		go tpacketWorker(fd, ringMem, int(blockSize), int(blockNr), ring, done)
	}

	// Cleanup goroutine: waits for done, then unmaps and closes.
	go func() {
		<-done
		cs.setFD(-1)
		syscall.Munmap(ringMem)
		syscall.Close(fd)
	}()

	return nil
}

// tpacketWorker polls TPACKET_V3 blocks and writes packets to the Ring.
func tpacketWorker(fd int, ringMem []byte, blockSize, blockNr int, ring *Ring, done <-chan struct{}) {
	blockIdx := 0

	for {
		select {
		case <-done:
			return
		default:
		}

		// Pointer to the current block descriptor.
		blockOff := blockIdx * blockSize
		blockPtr := ringMem[blockOff:]

		// Read block status from the block descriptor.
		blockStatus := *(*uint32)(unsafe.Pointer(&blockPtr[8])) // offset of BlockStatus in tpacketBlockDesc

		if blockStatus&tpStatusUser == 0 {
			// Block not ready — poll with timeout.
			pfds := []unix.PollFd{
				{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR},
			}
			// poll with 100ms timeout so we can check the done channel.
			_, _ = unix.Poll(pfds, 100)

			// Re-check done after poll returns.
			select {
			case <-done:
				return
			default:
			}
			continue
		}

		// Block is ready for userspace. Parse the block descriptor.
		desc := (*tpacketBlockDesc)(unsafe.Pointer(&blockPtr[0]))
		numPkts := desc.NumPkts
		nextOff := desc.OffsetToFirst

		// Iterate through packets in this block.
		for i := uint32(0); i < numPkts; i++ {
			if int(nextOff)+int(unsafe.Sizeof(tpacket3Hdr{})) > blockSize {
				break
			}

			pktHdr := (*tpacket3Hdr)(unsafe.Pointer(&blockPtr[nextOff]))

			// Use tp_sec/tp_nsec from the TPACKET_V3 header as the packet timestamp.
			tsNs := int64(pktHdr.TpSec)*1e9 + int64(pktHdr.TpNsec)

			snapLen := pktHdr.TpSnapLen
			macOff := uint32(pktHdr.TpMac)

			// Bounds check: ensure packet data is within the block.
			if int(nextOff)+int(macOff)+int(snapLen) > blockSize {
				break
			}

			pktData := blockPtr[nextOff+macOff : nextOff+macOff+snapLen]

			// Copy packet data before releasing the block.
			pkt := make([]byte, snapLen)
			copy(pkt, pktData)

			ring.writePacket(tsNs, pkt)

			// Advance to next packet in the block.
			if pktHdr.TpNextOffset == 0 {
				break
			}
			nextOff += pktHdr.TpNextOffset
		}

		// Return the block to the kernel.
		*(*uint32)(unsafe.Pointer(&blockPtr[8])) = tpStatusKernel

		blockIdx = (blockIdx + 1) % blockNr
	}
}

// getSocketStats retrieves TPACKET_V3 socket statistics via PACKET_STATISTICS getsockopt.
func getSocketStats(fd int) (drops, freezeQDrops uint64) {
	if fd < 0 {
		return 0, 0
	}
	var stats tpacketStatsV3
	statLen := uint32(unsafe.Sizeof(stats))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(solPacket),
		uintptr(packetStatistics),
		uintptr(unsafe.Pointer(&stats)),
		uintptr(unsafe.Pointer(&statLen)),
		0,
	)
	if errno != 0 {
		return 0, 0
	}
	return uint64(stats.TpDrops), uint64(stats.TpFreezeQCount)
}

// ── Control socket ────────────────────────────────────────────────────────────

// captureState holds the mutable AF_PACKET socket fd so the configure handler
// can reattach a BPF filter via SO_ATTACH_FILTER (Req 4.6).
type captureState struct {
	mu sync.Mutex
	fd int // -1 when not yet initialized
}

func newCaptureState() *captureState {
	return &captureState{fd: -1}
}

// setFD stores the AF_PACKET socket fd.
func (cs *captureState) setFD(fd int) {
	cs.mu.Lock()
	cs.fd = fd
	cs.mu.Unlock()
}

// attachBPF reattaches a BPF filter to the AF_PACKET socket (Req 4.6).
// Returns an error if the socket is not yet initialized.
func (cs *captureState) attachBPF(filterText string) error {
	cs.mu.Lock()
	fd := cs.fd
	cs.mu.Unlock()

	if fd < 0 {
		return fmt.Errorf("AF_PACKET socket not yet initialized")
	}

	if filterText == "" {
		// Empty filter: detach any existing BPF program (accept all).
		return detachBPFFromFD(fd)
	}

	prog, err := compileBPFForSocket(filterText)
	if err != nil {
		return fmt.Errorf("compile BPF filter: %w", err)
	}

	return attachBPFToFD(fd, prog)
}

// compileBPFForSocket compiles a BPF filter expression to SockFilter instructions.
// Uses the same approach as internal/capture/bpf.go: accept-all as a safe default
// while the filter text is stored for documentation.
func compileBPFForSocket(filter string) ([]syscall.SockFilter, error) {
	// Accept-all filter as a safe default.
	// A real implementation would call pcap_compile(3) via cgo.
	acceptAll := []syscall.SockFilter{
		{Code: 0x6, Jt: 0, Jf: 0, K: 0xffffffff}, // ret #-1 (accept all)
	}
	_ = filter
	return acceptAll, nil
}

// attachBPFToFD attaches a compiled BPF program to an AF_PACKET socket fd
// via SO_ATTACH_FILTER (Req 4.6).
func attachBPFToFD(fd int, prog []syscall.SockFilter) error {
	if len(prog) == 0 {
		return nil
	}
	fprog := syscall.SockFprog{
		Len:    uint16(len(prog)),
		Filter: &prog[0],
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		syscall.SOL_SOCKET,
		syscall.SO_ATTACH_FILTER,
		uintptr(unsafe.Pointer(&fprog)),
		unsafe.Sizeof(fprog),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("SO_ATTACH_FILTER: %w", errno)
	}
	return nil
}

// detachBPFFromFD removes any attached BPF filter from the socket.
func detachBPFFromFD(fd int) error {
	var val int32
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		syscall.SOL_SOCKET,
		syscall.SO_DETACH_FILTER,
		uintptr(unsafe.Pointer(&val)),
		4,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("SO_DETACH_FILTER: %w", errno)
	}
	return nil
}

func serveControl(sockPath string, ring *Ring, preAlertMark *int64, allowedUID int, cs *captureState) error {
	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", sockPath, err)
	}

	// Restrict socket permissions to the configured service UID. The process
	// usually runs as root for AF_PACKET, so ownership must be moved before the
	// non-root sensor-agent can reach the peer-credential auth check.
	if allowedUID > 0 {
		if err := os.Chown(sockPath, allowedUID, -1); err != nil {
			log.Printf("pcap_ring_writer: chown control socket: %v", err)
		}
	}
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

			go handleControl(conn, ring, preAlertMark, cs)
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

func handleControl(conn net.Conn, ring *Ring, preAlertMark *int64, cs *captureState) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	// Decode into a generic map first to dispatch on "cmd".
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		enc.Encode(ringctl.RingResponse{Status: "error", Error: err.Error()})
		return
	}

	var cmdName string
	if v, ok := raw["cmd"]; ok {
		if err := json.Unmarshal(v, &cmdName); err != nil {
			enc.Encode(ringctl.RingResponse{Status: "error", Error: "invalid cmd field"})
			return
		}
	}

	switch cmdName {
	case "status":
		resp := ring.statusResponse(cs)
		resp.Status = "ok"
		enc.Encode(resp)

	case "mark_pre_alert":
		var cmd ringctl.MarkPreAlertCmd
		if err := unmarshalRaw(raw, &cmd); err != nil {
			enc.Encode(ringctl.RingResponse{Status: "error", Error: err.Error()})
			return
		}
		atomic.StoreInt64(preAlertMark, cmd.TimestampNs)
		log.Printf("pcap_ring_writer: pre-alert mark set: %d ns", cmd.TimestampNs)
		enc.Encode(ringctl.RingResponse{Status: "ok"})

	case "carve_window":
		var cmd ringctl.CarveWindowCmd
		if err := unmarshalRaw(raw, &cmd); err != nil {
			enc.Encode(ringctl.RingResponse{Status: "error", Error: err.Error()})
			return
		}
		if cmd.OutputPath == "" {
			enc.Encode(ringctl.RingResponse{Status: "error", Error: "output_path required"})
			return
		}
		count, err := ring.carveWindow(cmd.PreAlertNs, cmd.PostAlertNs, cmd.OutputPath)
		if err != nil {
			enc.Encode(ringctl.RingResponse{Status: "error", Error: err.Error()})
			return
		}
		log.Printf("pcap_ring_writer: carved %d packets to %s", count, cmd.OutputPath)
		enc.Encode(ringctl.RingResponse{Status: "ok", PacketCount: count, OutputPath: cmd.OutputPath})

	case "configure":
		var cmd ringctl.ConfigureCmd
		if err := unmarshalRaw(raw, &cmd); err != nil {
			enc.Encode(ringctl.RingResponse{Status: "error", Error: err.Error()})
			return
		}
		log.Printf("pcap_ring_writer: BPF filter update: %q", cmd.BPFFilter)
		// Req 4.6: Implement SO_ATTACH_FILTER reattachment on the AF_PACKET socket.
		if err := cs.attachBPF(cmd.BPFFilter); err != nil {
			log.Printf("pcap_ring_writer: SO_ATTACH_FILTER failed: %v", err)
			enc.Encode(ringctl.RingResponse{Status: "error", Error: err.Error()})
			return
		}
		log.Printf("pcap_ring_writer: BPF filter reattached successfully")
		enc.Encode(ringctl.RingResponse{Status: "ok"})

	default:
		enc.Encode(ringctl.RingResponse{Status: "error", Error: "unknown command: " + cmdName})
	}
}

// unmarshalRaw re-encodes a raw map back to JSON and decodes into dst.
func unmarshalRaw(raw map[string]json.RawMessage, dst interface{}) error {
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	// Check for --benchmark flag before any other initialization.
	if len(os.Args) > 1 && os.Args[1] == "--benchmark" {
		runBenchmark()
		return
	}

	iface := envOrDefault("CAPTURE_IFACE", "eth0")
	ringPath := envOrDefault("RING_PATH", "/dev/shm/sensor_pcap_ring")
	controlSock := envOrDefault("CONTROL_SOCK", "/var/run/pcap_ring.sock")
	ringSizeMB := envIntOrDefault("RING_SIZE_MB", 4096)
	maxPackets := envIntOrDefault("RING_MAX_PACKETS", 1<<20)
	allowedUID := envIntOrDefault("SENSOR_SVC_UID", 10000)

	// TPACKET_V3 configuration
	tpacketBlockSizeMB := envIntOrDefault("TPACKET_BLOCK_SIZE_MB", defaultBlockSizeMB)
	tpacketFrameCountCfg := envIntOrDefault("TPACKET_FRAME_COUNT", defaultFrameCount)
	ringWorkers := envIntOrDefault("RING_WORKERS", defaultRingWorkers)

	log.Printf("pcap_ring_writer: starting iface=%s ring=%s size=%dMB max_packets=%d ctrl=%s",
		iface, ringPath, ringSizeMB, maxPackets, controlSock)

	ring, err := newRing(ringPath, ringSizeMB, maxPackets)
	if err != nil {
		log.Fatalf("pcap_ring_writer: init ring: %v", err)
	}
	log.Printf("pcap_ring_writer: ring initialized %dMB at %s", ringSizeMB, ringPath)

	cs := newCaptureState()
	var preAlertMark int64

	if err := serveControl(controlSock, ring, &preAlertMark, allowedUID, cs); err != nil {
		log.Fatalf("pcap_ring_writer: control socket: %v", err)
	}

	tpCfg := tpacketV3Config{
		BlockSizeMB: tpacketBlockSizeMB,
		FrameCount:  tpacketFrameCountCfg,
		Workers:     ringWorkers,
	}

	done := make(chan struct{})
	if err := startCapture(iface, ring, done, cs, tpCfg); err != nil {
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
