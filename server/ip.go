package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

type ipv4Packet struct {
	packet      []byte
	source      netip.Addr
	destination netip.Addr
}

func parseIPv4Packet(payload []byte) (ipv4Packet, error) {
	if len(payload) < 20 {
		return ipv4Packet{}, errors.New("short IPv4 packet")
	}
	if payload[0]>>4 != 4 {
		return ipv4Packet{}, errors.New("not an IPv4 packet")
	}
	ihl := int(payload[0]&0x0f) * 4
	if ihl < 20 {
		return ipv4Packet{}, fmt.Errorf("invalid IPv4 IHL %d", ihl)
	}
	if len(payload) < ihl {
		return ipv4Packet{}, errors.New("truncated IPv4 header")
	}
	totalLength := int(binary.BigEndian.Uint16(payload[2:4]))
	if totalLength < ihl {
		return ipv4Packet{}, fmt.Errorf("invalid IPv4 total length %d", totalLength)
	}
	if totalLength > len(payload) {
		return ipv4Packet{}, fmt.Errorf("truncated IPv4 payload: total=%d len=%d", totalLength, len(payload))
	}

	var source [4]byte
	var destination [4]byte
	copy(source[:], payload[12:16])
	copy(destination[:], payload[16:20])
	return ipv4Packet{
		packet:      payload[:totalLength],
		source:      netip.AddrFrom4(source),
		destination: netip.AddrFrom4(destination),
	}, nil
}
