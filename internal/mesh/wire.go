//go:build linux

// wire.go defines the framing protocol for pigeon-mesh TLS transport.
//
// # Connection Setup
//
// After TLS handshake, the initiator writes a single type byte to declare
// the connection mode:
//
//   - ConnPacket (0x01): multiplexed datagram connection (pooled).
//   - ConnStream (0x02): raw bidirectional stream (passed to memberlist).
//
// # Packet Framing (ConnPacket connections only)
//
// Each packet message on the connection uses the following layout:
//
//	+------------------+------------------+----------------+-----------+
//	| payload_len (4B) |  payload (var)   | from_len (4B)  | from (var)|
//	+------------------+------------------+----------------+-----------+
//
//	payload_len  uint32 big-endian   Length of payload in bytes.
//	payload      []byte              Memberlist gossip message.
//	from_len     uint32 big-endian   Length of from address string in bytes.
//	from         []byte              Sender's advertised address as "ip:port".
//
// Limits:
//   - payload_len  ≤ 65536 (64 KB, matches memberlist's UDP limit)
//   - from_len     ≤ 256   (ip:port strings are never this long)
//
// # Stream Mode (ConnStream connections)
//
// After the type byte, the TLS connection is passed through directly to
// memberlist's StreamCh. No additional framing is applied.
package mesh

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Connection type bytes written immediately after TLS handshake.
const (
	ConnPacket byte = 0x01 // Multiplexed datagram connection.
	ConnStream byte = 0x02 // Raw bidirectional stream.
)

// Protocol limits.
const (
	MaxPayloadSize = 64 * 1024 // 64 KB, matching memberlist's UDP limit.
	MaxFromSize    = 256       // ip:port strings are never this long.
)

// WritePacket encodes and writes a single packet-framed message.
func WritePacket(w io.Writer, payload []byte, from string) error {
	if len(payload) > MaxPayloadSize {
		return fmt.Errorf("payload too large: %d bytes (max %d)", len(payload), MaxPayloadSize)
	}
	if len(from) > MaxFromSize {
		return fmt.Errorf("from address too large: %d bytes (max %d)", len(from), MaxFromSize)
	}

	fromBytes := []byte(from)
	buf := make([]byte, 4+len(payload)+4+len(fromBytes))

	binary.BigEndian.PutUint32(buf[0:4], uint32(len(payload)))
	copy(buf[4:], payload)
	binary.BigEndian.PutUint32(buf[4+len(payload):], uint32(len(fromBytes)))
	copy(buf[4+len(payload)+4:], fromBytes)

	_, err := w.Write(buf)
	return err
}

// ReadPacket decodes a single packet-framed message.
// Returns the payload bytes and the sender's advertised address.
func ReadPacket(r io.Reader) (payload []byte, from string, err error) {
	// Read payload length.
	var plenBuf [4]byte
	if _, err := io.ReadFull(r, plenBuf[:]); err != nil {
		return nil, "", err
	}
	plen := binary.BigEndian.Uint32(plenBuf[:])
	if plen > MaxPayloadSize {
		return nil, "", fmt.Errorf("payload too large: %d bytes (max %d)", plen, MaxPayloadSize)
	}

	// Read payload.
	payload = make([]byte, plen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, "", fmt.Errorf("read payload: %w", err)
	}

	// Read from-address length.
	var flenBuf [4]byte
	if _, err := io.ReadFull(r, flenBuf[:]); err != nil {
		return nil, "", fmt.Errorf("read from length: %w", err)
	}
	flen := binary.BigEndian.Uint32(flenBuf[:])
	if flen > MaxFromSize {
		return nil, "", fmt.Errorf("from address too large: %d bytes (max %d)", flen, MaxFromSize)
	}

	// Read from-address.
	fromBuf := make([]byte, flen)
	if _, err := io.ReadFull(r, fromBuf); err != nil {
		return nil, "", fmt.Errorf("read from address: %w", err)
	}

	return payload, string(fromBuf), nil
}

// isTimeout reports whether err is a network timeout.
func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
