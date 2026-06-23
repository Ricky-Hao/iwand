package server

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	packetOpenReject = 0x11
	packetOpenAck    = 0x12
	packetOpen       = 0x13
	packetData       = 0x14
	packetEchoReq    = 0x15
	packetEchoResp   = 0x16
	packetClose      = 0x17
	packetDataEnc    = 0x18

	headerSize   = 8
	signSize     = 16
	signedHeader = headerSize + signSize
)

type tlv struct {
	typ   byte
	value []byte
}

type openRequest struct {
	username      string
	passwordBlock [16]byte
	mtu           uint16
	encrypt       bool
}

func signPacket(packet []byte) {
	digest := md5.New()
	digest.Write(packet[:headerSize])
	digest.Write([]byte("mw"))
	copy(packet[headerSize:signedHeader], digest.Sum(nil))
}

func verifyPacket(packet []byte) bool {
	if len(packet) < signedHeader {
		return false
	}
	digest := md5.New()
	digest.Write(packet[:headerSize])
	digest.Write([]byte("mw"))
	return bytes.Equal(packet[headerSize:signedHeader], digest.Sum(nil))
}

func appendTLV(packet []byte, tlvType byte, value ...byte) []byte {
	packet = append(packet, tlvType, byte(len(value)+2))
	return append(packet, value...)
}

func parseTLVs(data []byte) ([]tlv, error) {
	var tlvs []tlv
	for len(data) > 0 {
		if len(data) < 2 {
			return nil, errors.New("truncated TLV header")
		}
		tlvLength := int(data[1])
		if tlvLength < 2 || tlvLength > len(data) {
			return nil, fmt.Errorf("invalid TLV length %d", tlvLength)
		}
		tlvs = append(tlvs, tlv{
			typ:   data[0],
			value: data[2:tlvLength],
		})
		data = data[tlvLength:]
	}
	return tlvs, nil
}

func parseOpenPacket(packet []byte) (openRequest, error) {
	if len(packet) < signedHeader {
		return openRequest{}, errors.New("short OPEN packet")
	}
	if packet[0] != packetOpen {
		return openRequest{}, errors.New("not an OPEN packet")
	}
	if !verifyPacket(packet) {
		return openRequest{}, errors.New("invalid OPEN signature")
	}
	request := openRequest{
		mtu:     DefaultMTU,
		encrypt: packet[1] != 0,
	}
	var hasPassword bool
	tlvs, err := parseTLVs(packet[signedHeader:])
	if err != nil {
		return openRequest{}, err
	}
	for _, item := range tlvs {
		switch item.typ {
		case 1:
			request.username = string(item.value)
		case 2:
			if len(item.value) != 16 {
				return openRequest{}, fmt.Errorf("invalid password TLV length %d", len(item.value))
			}
			copy(request.passwordBlock[:], item.value)
			hasPassword = true
		case 3:
			if len(item.value) < 2 {
				return openRequest{}, fmt.Errorf("invalid MTU TLV length %d", len(item.value))
			}
			request.mtu = binary.BigEndian.Uint16(item.value[:2])
		case 8:
			if len(item.value) > 0 {
				request.encrypt = item.value[0] != 0
			}
		}
	}
	if request.username == "" {
		return openRequest{}, errors.New("missing username TLV")
	}
	if !hasPassword {
		return openRequest{}, errors.New("missing password TLV")
	}
	if request.mtu < MinMTU || request.mtu > MaxMTU {
		return openRequest{}, fmt.Errorf("invalid client MTU %d", request.mtu)
	}
	return request, nil
}

func encryptedPassword(username string, password string) ([16]byte, error) {
	key := md5.Sum(append([]byte("mw"), []byte(username)...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return [16]byte{}, err
	}
	var plain [16]byte
	copy(plain[:], []byte(password))
	var encrypted [16]byte
	block.Encrypt(encrypted[:], plain[:])
	return encrypted, nil
}

func passwordMatches(username string, password string, block [16]byte) (bool, error) {
	expected, err := encryptedPassword(username, password)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(block[:], expected[:]) == 1, nil
}

func deriveXORKey(username string, password string) [8]byte {
	hash := md5.Sum([]byte(username + password))
	var key [8]byte
	copy(key[:], hash[:8])
	return key
}

func xorData(key [8]byte, data []byte) {
	for index := range data {
		data[index] ^= key[index&7]
	}
}

func buildOpenReject() []byte {
	packet := make([]byte, signedHeader)
	packet[0] = packetOpenReject
	signPacket(packet)
	return packet
}

func buildOpenAck(token [2]byte, sessionID [4]byte, mtu uint16, address netip.Addr, dns []netip.Addr, encrypt bool) []byte {
	packet := make([]byte, signedHeader, 64)
	packet[0] = packetOpenAck
	if encrypt {
		packet[1] = 1
	}
	copy(packet[2:4], token[:])
	copy(packet[4:8], sessionID[:])
	signPacket(packet)
	packet = appendTLV(packet, 3, byte(mtu>>8), byte(mtu))
	addressBytes := address.As4()
	packet = appendTLV(packet, 4, addressBytes[:]...)
	if len(dns) == 1 {
		dns0 := dns[0].As4()
		packet = appendTLV(packet, 5, dns0[:]...)
	} else if len(dns) >= 2 {
		dns0 := dns[0].As4()
		dns1 := dns[1].As4()
		var dnsPair [8]byte
		copy(dnsPair[:4], dns0[:])
		copy(dnsPair[4:], dns1[:])
		packet = appendTLV(packet, 6, dnsPair[:]...)
	}
	if encrypt {
		packet = appendTLV(packet, 8, 1)
	} else {
		packet = appendTLV(packet, 8, 0)
	}
	return packet
}

func buildEchoResp(token [2]byte, sessionID [4]byte, payload []byte) []byte {
	packet := make([]byte, signedHeader+len(payload))
	packet[0] = packetEchoResp
	copy(packet[2:4], token[:])
	copy(packet[4:8], sessionID[:])
	signPacket(packet)
	copy(packet[signedHeader:], payload)
	return packet
}

func buildDataPacket(token [2]byte, sessionID [4]byte, payload []byte, encrypt bool, key [8]byte) []byte {
	packet := make([]byte, headerSize+len(payload))
	if encrypt {
		packet[0] = packetDataEnc
		packet[1] = 1
	} else {
		packet[0] = packetData
	}
	copy(packet[2:4], token[:])
	copy(packet[4:8], sessionID[:])
	copy(packet[headerSize:], payload)
	if encrypt {
		xorData(key, packet[headerSize:])
	}
	return packet
}
