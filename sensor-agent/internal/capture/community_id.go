package capture

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
)

// CommunityIDVersion is the Community ID spec version implemented here.
const CommunityIDVersion = 1

// Flow5Tuple represents a network flow 5-tuple.
type Flow5Tuple struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// ComputeCommunityID computes the Community ID v1 hash for a 5-tuple.
// The Community ID spec: https://github.com/corelight/community-id-spec
//
// Format: "1:<base64(sha1(seed + ordered_tuple))>"
// The tuple is ordered so that the smaller (src, sport) pair comes first.
func ComputeCommunityID(flow Flow5Tuple, seed uint16) (string, error) {
	// Normalize: ensure src < dst ordering for symmetric flows
	src, dst, sport, dport := orderTuple(flow)

	h := sha1.New()

	// Write seed (2 bytes, big-endian)
	var seedBuf [2]byte
	binary.BigEndian.PutUint16(seedBuf[:], seed)
	h.Write(seedBuf[:])

	// Write source IP: 4 bytes for IPv4, 16 bytes for IPv6 (per community-id spec)
	srcIP := normalizeIP(src)
	dstIP := normalizeIP(dst)
	if srcIP == nil || dstIP == nil {
		return "", fmt.Errorf("invalid IP address in flow tuple")
	}
	h.Write(srcIP)
	h.Write(dstIP)

	// Write protocol (1 byte)
	h.Write([]byte{flow.Proto})

	// Write padding (1 byte)
	h.Write([]byte{0})

	// Write source port (2 bytes, big-endian)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], sport)
	h.Write(portBuf[:])

	// Write destination port (2 bytes, big-endian)
	binary.BigEndian.PutUint16(portBuf[:], dport)
	h.Write(portBuf[:])

	digest := h.Sum(nil)
	encoded := base64.StdEncoding.EncodeToString(digest)

	return fmt.Sprintf("%d:%s", CommunityIDVersion, encoded), nil
}

// orderTuple returns the tuple in canonical order (smaller address/port first).
// This ensures the same Community ID for both directions of a flow.
func orderTuple(flow Flow5Tuple) (src, dst net.IP, sport, dport uint16) {
	src = flow.SrcIP
	dst = flow.DstIP
	sport = flow.SrcPort
	dport = flow.DstPort

	// Compare IPs using their normalized (4 or 16 byte) form
	srcNorm := normalizeIP(flow.SrcIP)
	dstNorm := normalizeIP(flow.DstIP)

	cmp := compareIPs(srcNorm, dstNorm)
	if cmp > 0 || (cmp == 0 && flow.SrcPort > flow.DstPort) {
		// Swap to put smaller first
		src, dst = flow.DstIP, flow.SrcIP
		sport, dport = flow.DstPort, flow.SrcPort
	}

	return
}

// normalizeIP returns the canonical byte representation for hashing:
// 4 bytes for IPv4, 16 bytes for IPv6, per the community-id spec.
func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// compareIPs compares two IP addresses lexicographically.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareIPs(a, b net.IP) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// ParseFlow5Tuple parses a flow 5-tuple from string components.
func ParseFlow5Tuple(srcIP, dstIP string, srcPort, dstPort uint16, proto uint8) (Flow5Tuple, error) {
	src := net.ParseIP(srcIP)
	if src == nil {
		return Flow5Tuple{}, fmt.Errorf("invalid source IP: %s", srcIP)
	}
	dst := net.ParseIP(dstIP)
	if dst == nil {
		return Flow5Tuple{}, fmt.Errorf("invalid destination IP: %s", dstIP)
	}
	return Flow5Tuple{
		SrcIP:   src,
		DstIP:   dst,
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   proto,
	}, nil
}
