package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConfigLoadDefaultsAndValidation(t *testing.T) {
	t.Parallel()
	config, err := DecodeConfig(strings.NewReader(`{
		"users": [
			{"username": "alice", "password": "alice-pass", "address": "10.20.30.10"},
			{"username": "bob", "password": "bob-pass", "address": "10.20.30.11", "allow_encrypt": false}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if config.Listen != DefaultListen {
		t.Fatalf("unexpected default listen: %s", config.Listen)
	}
	if config.MTU != DefaultMTU {
		t.Fatalf("unexpected default mtu: %d", config.MTU)
	}
	normalized, err := config.normalized()
	if err != nil {
		t.Fatal(err)
	}
	if !normalized.users["alice"].allowEncrypt {
		t.Fatal("allow_encrypt should default to true")
	}
	if normalized.users["bob"].allowEncrypt {
		t.Fatal("explicit allow_encrypt=false was ignored")
	}
	if normalized.exit.enabled {
		t.Fatal("exit mode should default to disabled")
	}
}

func TestExitConfigDefaultsAndValidation(t *testing.T) {
	t.Parallel()
	config, err := DecodeConfig(strings.NewReader(`{
		"users": [
			{"username": "alice", "password": "alice-pass", "address": "10.20.30.10"}
		],
		"exit": {
			"enabled": true,
			"tun_address": "10.20.30.1/24"
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := config.normalized()
	if err != nil {
		t.Fatal(err)
	}
	if !normalized.exit.enabled {
		t.Fatal("exit mode should be enabled")
	}
	if normalized.exit.tunName != DefaultExitTUNName {
		t.Fatalf("unexpected default tun name: %s", normalized.exit.tunName)
	}
	if normalized.exit.mtu != DefaultMTU {
		t.Fatalf("unexpected default exit mtu: %d", normalized.exit.mtu)
	}
	if !normalized.exit.strictSource {
		t.Fatal("strict_source should default to true")
	}

	strictSource := false
	config.Exit.StrictSource = &strictSource
	normalized, err = config.normalized()
	if err != nil {
		t.Fatal(err)
	}
	if normalized.exit.strictSource {
		t.Fatal("strict_source=false was ignored")
	}

	_, err = DecodeConfig(strings.NewReader(`{
		"users": [
			{"username": "alice", "password": "alice-pass", "address": "10.20.30.10"}
		],
		"exit": {
			"enabled": true
		}
	}`))
	if err == nil {
		t.Fatal("missing exit.tun_address should be rejected when exit is enabled")
	}
}

func TestServerPacketSmoke(t *testing.T) {
	t.Parallel()
	server, conn, cleanup := startPacketServer(t)
	defer cleanup()
	_ = server

	alice := openClient(t, conn.LocalAddr().String(), "alice", "alice-pass", 1400, true)
	defer alice.Close()
	if alice.ack.assignedIP != netip.MustParseAddr("10.20.30.10") {
		t.Fatalf("unexpected alice assigned IP: %s", alice.ack.assignedIP)
	}
	if !alice.ack.encrypt {
		t.Fatal("alice should negotiate DATA_ENC")
	}

	bob := openClient(t, conn.LocalAddr().String(), "bob", "bob-pass", 1400, true)
	defer bob.Close()
	if bob.ack.assignedIP != netip.MustParseAddr("10.20.30.11") {
		t.Fatalf("unexpected bob assigned IP: %s", bob.ack.assignedIP)
	}
	if bob.ack.assignedIP == alice.ack.assignedIP {
		t.Fatal("assigned IPs should differ")
	}

	rejected := dialUDPClient(t, conn.LocalAddr().String())
	defer rejected.Close()
	sendPacket(t, rejected, buildOpenPacket(t, "bob", "wrong-pass", 1400, true))
	reject := readPacket(t, rejected)
	if reject[0] != packetOpenReject || !verifyPacket(reject) {
		t.Fatalf("expected signed OPENREJ, got type=%x len=%d", reject[0], len(reject))
	}

	echoReqPayload := make([]byte, 36)
	binary.LittleEndian.PutUint64(echoReqPayload[:8], uint64(time.Now().UnixMicro()))
	sendPacket(t, alice.UDPConn, buildEchoReq(alice.ack.token, alice.ack.sessionID, echoReqPayload))
	echoResp := readPacket(t, alice.UDPConn)
	if echoResp[0] != packetEchoResp || !verifyPacket(echoResp) {
		t.Fatalf("invalid ECHORESP type=%x len=%d", echoResp[0], len(echoResp))
	}
	if !bytes.Equal(echoResp[signedHeader:], echoReqPayload) {
		t.Fatal("ECHORESP did not preserve payload")
	}

	payload := testIPv4Packet(netip.MustParseAddr("10.20.30.10"), netip.MustParseAddr("10.20.30.99"))
	encrypted := append([]byte(nil), payload...)
	xorData(deriveXORKey("alice", "alice-pass"), encrypted)
	sendPacket(t, alice.UDPConn, buildRawDataPacket(packetDataEnc, alice.ack.token, alice.ack.sessionID, encrypted))
	dataEcho := readPacket(t, alice.UDPConn)
	if dataEcho[0] != packetDataEnc || dataEcho[1] != 1 {
		t.Fatalf("expected DATA_ENC echo, got type=%x flags=%x", dataEcho[0], dataEcho[1])
	}
	decryptedEcho := append([]byte(nil), dataEcho[headerSize:]...)
	xorData(deriveXORKey("alice", "alice-pass"), decryptedEcho)
	if !bytes.Equal(decryptedEcho, payload) {
		t.Fatal("DATA_ENC XOR round-trip mismatch")
	}

	forwardPayload := testIPv4Packet(netip.MustParseAddr("10.20.30.10"), netip.MustParseAddr("10.20.30.11"))
	encryptedForward := append([]byte(nil), forwardPayload...)
	xorData(deriveXORKey("alice", "alice-pass"), encryptedForward)
	sendPacket(t, alice.UDPConn, buildRawDataPacket(packetDataEnc, alice.ack.token, alice.ack.sessionID, encryptedForward))
	forwarded := readPacket(t, bob.UDPConn)
	if forwarded[0] != packetDataEnc {
		t.Fatalf("expected encrypted forwarded packet for bob, got type=%x", forwarded[0])
	}
	decryptedForward := append([]byte(nil), forwarded[headerSize:]...)
	xorData(deriveXORKey("bob", "bob-pass"), decryptedForward)
	if !bytes.Equal(decryptedForward, forwardPayload) {
		t.Fatal("forwarded DATA_ENC payload mismatch")
	}

	sendPacket(t, alice.UDPConn, buildClosePacket(alice.ack.token, alice.ack.sessionID))
	time.Sleep(20 * time.Millisecond)
	sendPacket(t, alice.UDPConn, buildEchoReq(alice.ack.token, alice.ack.sessionID, echoReqPayload))
	expectNoPacket(t, alice.UDPConn)
}

func TestServerRejectsInvalidSession(t *testing.T) {
	t.Parallel()
	_, conn, cleanup := startPacketServer(t)
	defer cleanup()

	alice := openClient(t, conn.LocalAddr().String(), "alice", "alice-pass", 1400, true)
	defer alice.Close()

	badToken := alice.ack.token
	badToken[0] ^= 0xff
	sendPacket(t, alice.UDPConn, buildEchoReq(badToken, alice.ack.sessionID, make([]byte, 36)))
	expectNoPacket(t, alice.UDPConn)

	payload := testIPv4Packet(netip.MustParseAddr("10.20.30.10"), netip.MustParseAddr("10.20.30.99"))
	sendPacket(t, alice.UDPConn, buildRawDataPacket(packetData, badToken, alice.ack.sessionID, payload))
	expectNoPacket(t, alice.UDPConn)
}

func TestParseIPv4PacketValidation(t *testing.T) {
	t.Parallel()
	payload := append(testIPv4Packet(netip.MustParseAddr("10.20.30.10"), netip.MustParseAddr("8.8.8.8")), 0xaa, 0xbb)
	parsed, err := parseIPv4Packet(payload)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.source != netip.MustParseAddr("10.20.30.10") {
		t.Fatalf("unexpected source: %s", parsed.source)
	}
	if parsed.destination != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("unexpected destination: %s", parsed.destination)
	}
	if len(parsed.packet) != len(payload)-2 {
		t.Fatalf("IPv4 parser should trim trailing bytes using total length, got len=%d", len(parsed.packet))
	}

	if _, err = parseIPv4Packet([]byte{0x60, 0, 0, 0}); err == nil {
		t.Fatal("non-IPv4 packet should be rejected")
	}
	truncated := testIPv4Packet(netip.MustParseAddr("10.20.30.10"), netip.MustParseAddr("8.8.8.8"))
	binary.BigEndian.PutUint16(truncated[2:4], uint16(len(truncated)+1))
	if _, err = parseIPv4Packet(truncated); err == nil {
		t.Fatal("truncated total length should be rejected")
	}
}

func TestExitModeWritesUnknownDestinationToDevice(t *testing.T) {
	t.Parallel()
	device := newFakePacketDevice()
	_, conn, cleanup := startPacketServerWithConfig(t, exitTestConfig(), device)
	defer cleanup()

	alice := openClient(t, conn.LocalAddr().String(), "alice", "alice-pass", 1400, true)
	defer alice.Close()

	payload := testIPv4Packet(netip.MustParseAddr("10.20.30.10"), netip.MustParseAddr("8.8.8.8"))
	encrypted := append([]byte(nil), payload...)
	xorData(deriveXORKey("alice", "alice-pass"), encrypted)
	sendPacket(t, alice.UDPConn, buildRawDataPacket(packetDataEnc, alice.ack.token, alice.ack.sessionID, encrypted))

	written := readDeviceWrite(t, device)
	if !bytes.Equal(written, payload) {
		t.Fatalf("exit device write mismatch: got %x want %x", written, payload)
	}
	expectNoPacket(t, alice.UDPConn)
}

func TestExitModeStrictSourceRejectsSpoofedPacket(t *testing.T) {
	t.Parallel()
	device := newFakePacketDevice()
	_, conn, cleanup := startPacketServerWithConfig(t, exitTestConfig(), device)
	defer cleanup()

	alice := openClient(t, conn.LocalAddr().String(), "alice", "alice-pass", 1400, true)
	defer alice.Close()

	payload := testIPv4Packet(netip.MustParseAddr("10.20.30.99"), netip.MustParseAddr("8.8.8.8"))
	encrypted := append([]byte(nil), payload...)
	xorData(deriveXORKey("alice", "alice-pass"), encrypted)
	sendPacket(t, alice.UDPConn, buildRawDataPacket(packetDataEnc, alice.ack.token, alice.ack.sessionID, encrypted))

	expectNoDeviceWrite(t, device)
	expectNoPacket(t, alice.UDPConn)
}

func TestExitModeReadDemuxesReturnPacketToClient(t *testing.T) {
	t.Parallel()
	device := newFakePacketDevice()
	_, conn, cleanup := startPacketServerWithConfig(t, exitTestConfig(), device)
	defer cleanup()

	alice := openClient(t, conn.LocalAddr().String(), "alice", "alice-pass", 1400, true)
	defer alice.Close()

	payload := testIPv4Packet(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.20.30.10"))
	device.injectRead(payload)
	response := readPacket(t, alice.UDPConn)
	if response[0] != packetDataEnc || response[1] != 1 {
		t.Fatalf("expected DATA_ENC return packet, got type=%x flags=%x", response[0], response[1])
	}
	decrypted := append([]byte(nil), response[headerSize:]...)
	xorData(deriveXORKey("alice", "alice-pass"), decrypted)
	if !bytes.Equal(decrypted, payload) {
		t.Fatal("return packet payload mismatch")
	}
}

func TestExitModePreservesInternalForwarding(t *testing.T) {
	t.Parallel()
	device := newFakePacketDevice()
	_, conn, cleanup := startPacketServerWithConfig(t, exitTestConfig(), device)
	defer cleanup()

	alice := openClient(t, conn.LocalAddr().String(), "alice", "alice-pass", 1400, true)
	defer alice.Close()
	bob := openClient(t, conn.LocalAddr().String(), "bob", "bob-pass", 1400, true)
	defer bob.Close()

	payload := testIPv4Packet(netip.MustParseAddr("10.20.30.10"), netip.MustParseAddr("10.20.30.11"))
	encrypted := append([]byte(nil), payload...)
	xorData(deriveXORKey("alice", "alice-pass"), encrypted)
	sendPacket(t, alice.UDPConn, buildRawDataPacket(packetDataEnc, alice.ack.token, alice.ack.sessionID, encrypted))

	forwarded := readPacket(t, bob.UDPConn)
	if forwarded[0] != packetDataEnc {
		t.Fatalf("expected DATA_ENC forwarded packet, got type=%x", forwarded[0])
	}
	decrypted := append([]byte(nil), forwarded[headerSize:]...)
	xorData(deriveXORKey("bob", "bob-pass"), decrypted)
	if !bytes.Equal(decrypted, payload) {
		t.Fatal("forwarded payload mismatch")
	}
	expectNoDeviceWrite(t, device)
}

func startPacketServer(t *testing.T) (*Server, *net.UDPConn, func()) {
	t.Helper()
	return startPacketServerWithConfig(t, testServerConfig(), nil)
}

func testServerConfig() Config {
	allowEncrypt := true
	return Config{
		Listen: "127.0.0.1:0",
		MTU:    1400,
		DNS:    []string{"1.1.1.1", "8.8.8.8"},
		Users: []UserConfig{
			{Username: "alice", Password: "alice-pass", Address: "10.20.30.10", AllowEncrypt: &allowEncrypt},
			{Username: "bob", Password: "bob-pass", Address: "10.20.30.11", AllowEncrypt: &allowEncrypt},
		},
	}
}

func exitTestConfig() Config {
	config := testServerConfig()
	config.Exit = ExitConfig{
		Enabled:    true,
		TUNName:    "iwandtest0",
		TUNAddress: "10.20.30.1/24",
		MTU:        1400,
	}
	return config
}

func startPacketServerWithConfig(t *testing.T, config Config, device packetDevice) (*Server, *net.UDPConn, func()) {
	t.Helper()
	iwanServer, err := newServer(config, log.New(io.Discard, "", 0), device)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := config.UDPAddr()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- iwanServer.Serve(ctx, conn)
	}()
	cleanup := func() {
		cancel()
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("server did not stop")
		}
	}
	return iwanServer, conn, cleanup
}

type fakePacketDevice struct {
	reads  chan []byte
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakePacketDevice() *fakePacketDevice {
	return &fakePacketDevice{
		reads:  make(chan []byte, 8),
		writes: make(chan []byte, 8),
		closed: make(chan struct{}),
	}
}

func (f *fakePacketDevice) Read(buffer []byte) (int, error) {
	select {
	case packet := <-f.reads:
		copy(buffer, packet)
		return len(packet), nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakePacketDevice) Write(packet []byte) (int, error) {
	clone := append([]byte(nil), packet...)
	select {
	case f.writes <- clone:
		return len(packet), nil
	case <-f.closed:
		return 0, net.ErrClosed
	}
}

func (f *fakePacketDevice) Close() error {
	f.once.Do(func() {
		close(f.closed)
	})
	return nil
}

func (f *fakePacketDevice) injectRead(packet []byte) {
	f.reads <- append([]byte(nil), packet...)
}

func readDeviceWrite(t *testing.T, device *fakePacketDevice) []byte {
	t.Helper()
	select {
	case packet := <-device.writes:
		return packet
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for exit device write")
		return nil
	}
}

func expectNoDeviceWrite(t *testing.T, device *fakePacketDevice) {
	t.Helper()
	select {
	case packet := <-device.writes:
		t.Fatalf("unexpected exit device write: %x", packet)
	case <-time.After(150 * time.Millisecond):
	}
}

type testClient struct {
	*net.UDPConn
	ack openAck
}

type openAck struct {
	token      [2]byte
	sessionID  [4]byte
	assignedIP netip.Addr
	encrypt    bool
}

func openClient(t *testing.T, serverAddr string, username string, password string, mtu uint16, encrypt bool) testClient {
	t.Helper()
	client := dialUDPClient(t, serverAddr)
	sendPacket(t, client, buildOpenPacket(t, username, password, mtu, encrypt))
	response := readPacket(t, client)
	if response[0] != packetOpenAck {
		t.Fatalf("expected OPENACK, got type=%x len=%d", response[0], len(response))
	}
	ack, err := parseOpenAck(response)
	if err != nil {
		t.Fatal(err)
	}
	return testClient{UDPConn: client, ack: ack}
}

func dialUDPClient(t *testing.T, serverAddr string) *net.UDPConn {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func buildOpenPacket(t *testing.T, username string, password string, mtu uint16, encrypt bool) []byte {
	t.Helper()
	packet := make([]byte, signedHeader, 128)
	packet[0] = packetOpen
	if encrypt {
		packet[1] = 1
	}
	signPacket(packet)
	packet = appendTLV(packet, 3, byte(mtu>>8), byte(mtu))
	packet = appendTLV(packet, 1, []byte(username)...)
	passwordBlock, err := encryptedPassword(username, password)
	if err != nil {
		t.Fatal(err)
	}
	packet = appendTLV(packet, 2, passwordBlock[:]...)
	if encrypt {
		packet = appendTLV(packet, 8, 1)
	}
	return packet
}

func parseOpenAck(packet []byte) (openAck, error) {
	if len(packet) < signedHeader || packet[0] != packetOpenAck || !verifyPacket(packet) {
		return openAck{}, io.ErrUnexpectedEOF
	}
	ack := openAck{
		encrypt: packet[1] != 0,
	}
	copy(ack.token[:], packet[2:4])
	copy(ack.sessionID[:], packet[4:8])
	tlvs, err := parseTLVs(packet[signedHeader:])
	if err != nil {
		return openAck{}, err
	}
	for _, item := range tlvs {
		switch item.typ {
		case 4:
			if len(item.value) >= 4 {
				var address [4]byte
				copy(address[:], item.value[:4])
				ack.assignedIP = netip.AddrFrom4(address)
			}
		case 8:
			if len(item.value) > 0 {
				ack.encrypt = item.value[0] != 0
			}
		}
	}
	return ack, nil
}

func buildEchoReq(token [2]byte, sessionID [4]byte, payload []byte) []byte {
	packet := make([]byte, signedHeader+len(payload))
	packet[0] = packetEchoReq
	copy(packet[2:4], token[:])
	copy(packet[4:8], sessionID[:])
	signPacket(packet)
	copy(packet[signedHeader:], payload)
	return packet
}

func buildClosePacket(token [2]byte, sessionID [4]byte) []byte {
	packet := make([]byte, signedHeader)
	packet[0] = packetClose
	copy(packet[2:4], token[:])
	copy(packet[4:8], sessionID[:])
	signPacket(packet)
	return packet
}

func buildRawDataPacket(packetType byte, token [2]byte, sessionID [4]byte, payload []byte) []byte {
	packet := make([]byte, headerSize+len(payload))
	packet[0] = packetType
	if packetType == packetDataEnc {
		packet[1] = 1
	}
	copy(packet[2:4], token[:])
	copy(packet[4:8], sessionID[:])
	copy(packet[headerSize:], payload)
	return packet
}

func testIPv4Packet(source netip.Addr, destination netip.Addr) []byte {
	packet := make([]byte, 20+4)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	copy(packet[20:], []byte{1, 2, 3, 4})
	return packet
}

func sendPacket(t *testing.T, client *net.UDPConn, packet []byte) {
	t.Helper()
	_ = client.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
}

func readPacket(t *testing.T, client *net.UDPConn) []byte {
	t.Helper()
	buffer := make([]byte, 4096)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, n)
	copy(packet, buffer[:n])
	return packet
}

func expectNoPacket(t *testing.T, client *net.UDPConn) {
	t.Helper()
	buffer := make([]byte, 4096)
	_ = client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	n, err := client.Read(buffer)
	if err == nil {
		t.Fatalf("unexpected packet: type=%x len=%d", buffer[0], n)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected read timeout, got %v", err)
	}
}
