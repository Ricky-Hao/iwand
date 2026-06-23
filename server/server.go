package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Server struct {
	config normalizedConfig
	logger *log.Logger

	access    sync.Mutex
	sessions  map[sessionKey]*session
	byAddress map[netip.Addr]*session
}

type sessionKey struct {
	remote    string
	token     [2]byte
	sessionID [4]byte
}

type session struct {
	key       sessionKey
	user      *configuredUser
	remote    *net.UDPAddr
	encrypt   bool
	mtu       uint16
	createdAt time.Time
	lastSeen  time.Time
}

type outboundSession struct {
	remote    *net.UDPAddr
	token     [2]byte
	sessionID [4]byte
	encrypt   bool
	xorKey    [8]byte
}

func New(config Config, logger *log.Logger) (*Server, error) {
	normalized, err := config.normalized()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{
		config:    normalized,
		logger:    logger,
		sessions:  make(map[sessionKey]*session),
		byAddress: make(map[netip.Addr]*session),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.config.listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return s.Serve(ctx, conn)
}

func (s *Server) Serve(ctx context.Context, conn *net.UDPConn) error {
	s.logger.Printf("listening on %s", conn.LocalAddr())
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buffer := make([]byte, 4096)
	for {
		n, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return err
		}
		packet := make([]byte, n)
		copy(packet, buffer[:n])
		if err = s.handlePacket(conn, remote, packet); err != nil {
			s.logger.Printf("handle packet from %s: %v", remote, err)
		}
	}
}

func (s *Server) handlePacket(conn *net.UDPConn, remote *net.UDPAddr, packet []byte) error {
	if len(packet) < headerSize {
		return nil
	}
	switch packet[0] {
	case packetOpen:
		return s.handleOpen(conn, remote, packet)
	case packetEchoReq:
		return s.handleEchoReq(conn, remote, packet)
	case packetClose:
		return s.handleClose(remote, packet)
	case packetData, packetDataEnc:
		return s.handleData(conn, remote, packet)
	default:
		return nil
	}
}

func (s *Server) handleOpen(conn *net.UDPConn, remote *net.UDPAddr, packet []byte) error {
	request, err := parseOpenPacket(packet)
	if err != nil {
		_, writeErr := conn.WriteToUDP(buildOpenReject(), remote)
		if writeErr != nil {
			return writeErr
		}
		return nil
	}

	user, exists := s.config.users[request.username]
	if !exists {
		_, writeErr := conn.WriteToUDP(buildOpenReject(), remote)
		if writeErr != nil {
			return writeErr
		}
		return nil
	}
	matches, err := passwordMatches(user.username, user.password, request.passwordBlock)
	if err != nil {
		return err
	}
	if !matches {
		_, writeErr := conn.WriteToUDP(buildOpenReject(), remote)
		if writeErr != nil {
			return writeErr
		}
		return nil
	}

	token, sessionID, err := newSessionIDs()
	if err != nil {
		return err
	}
	effectiveMTU := s.config.mtu
	if request.mtu < effectiveMTU {
		effectiveMTU = request.mtu
	}
	encrypt := request.encrypt && user.allowEncrypt
	now := time.Now()
	key := sessionKey{
		remote:    remote.String(),
		token:     token,
		sessionID: sessionID,
	}
	nextSession := &session{
		key:       key,
		user:      user,
		remote:    cloneUDPAddr(remote),
		encrypt:   encrypt,
		mtu:       effectiveMTU,
		createdAt: now,
		lastSeen:  now,
	}

	s.access.Lock()
	s.removeSessionsForRemoteOrUserLocked(remote.String(), user.username)
	s.sessions[key] = nextSession
	s.byAddress[user.address] = nextSession
	s.access.Unlock()

	response := buildOpenAck(token, sessionID, effectiveMTU, user.address, s.config.dns, encrypt)
	_, err = conn.WriteToUDP(response, remote)
	return err
}

func (s *Server) handleEchoReq(conn *net.UDPConn, remote *net.UDPAddr, packet []byte) error {
	if !verifyPacket(packet) {
		return nil
	}
	outbound, ok := s.outboundForPacket(remote, packet)
	if !ok {
		return nil
	}
	response := buildEchoResp(outbound.token, outbound.sessionID, packet[signedHeader:])
	_, err := conn.WriteToUDP(response, outbound.remote)
	return err
}

func (s *Server) handleClose(remote *net.UDPAddr, packet []byte) error {
	if !verifyPacket(packet) {
		return nil
	}
	key := keyFromPacket(remote, packet)
	s.access.Lock()
	defer s.access.Unlock()
	current, ok := s.sessions[key]
	if !ok {
		return nil
	}
	s.removeSessionLocked(current)
	return nil
}

func (s *Server) handleData(conn *net.UDPConn, remote *net.UDPAddr, packet []byte) error {
	if len(packet) <= headerSize {
		return nil
	}
	source, ok := s.sessionForPacket(remote, packet)
	if !ok {
		return nil
	}
	if packet[0] == packetDataEnc && !source.encrypt {
		return nil
	}
	if packet[0] == packetData && source.encrypt {
		return nil
	}

	payload := make([]byte, len(packet)-headerSize)
	copy(payload, packet[headerSize:])
	if packet[0] == packetDataEnc {
		xorData(source.xorKey, payload)
	}

	target := s.routeTarget(payload)
	if target == nil {
		target = source
	}
	response := buildDataPacket(target.token, target.sessionID, payload, target.encrypt, target.xorKey)
	_, err := conn.WriteToUDP(response, target.remote)
	return err
}

func (s *Server) outboundForPacket(remote *net.UDPAddr, packet []byte) (outboundSession, bool) {
	session, ok := s.sessionForPacket(remote, packet)
	if !ok {
		return outboundSession{}, false
	}
	return *session, true
}

func (s *Server) sessionForPacket(remote *net.UDPAddr, packet []byte) (*outboundSession, bool) {
	key := keyFromPacket(remote, packet)
	s.access.Lock()
	defer s.access.Unlock()
	current, ok := s.sessions[key]
	if !ok {
		return nil, false
	}
	current.lastSeen = time.Now()
	return sessionToOutbound(current), true
}

func (s *Server) routeTarget(payload []byte) *outboundSession {
	destination, ok := ipv4Destination(payload)
	if !ok {
		return nil
	}
	s.access.Lock()
	defer s.access.Unlock()
	current, ok := s.byAddress[destination]
	if !ok {
		return nil
	}
	return sessionToOutbound(current)
}

func sessionToOutbound(current *session) *outboundSession {
	return &outboundSession{
		remote:    cloneUDPAddr(current.remote),
		token:     current.key.token,
		sessionID: current.key.sessionID,
		encrypt:   current.encrypt,
		xorKey:    current.user.xorKey,
	}
}

func (s *Server) removeSessionsForRemoteOrUserLocked(remote string, username string) {
	for _, current := range s.sessions {
		if current.key.remote == remote || current.user.username == username {
			s.removeSessionLocked(current)
		}
	}
}

func (s *Server) removeSessionLocked(current *session) {
	delete(s.sessions, current.key)
	if s.byAddress[current.user.address] == current {
		delete(s.byAddress, current.user.address)
	}
}

func keyFromPacket(remote *net.UDPAddr, packet []byte) sessionKey {
	var token [2]byte
	var sessionID [4]byte
	copy(token[:], packet[2:4])
	copy(sessionID[:], packet[4:8])
	return sessionKey{
		remote:    remote.String(),
		token:     token,
		sessionID: sessionID,
	}
}

func newSessionIDs() ([2]byte, [4]byte, error) {
	var token [2]byte
	var sessionID [4]byte
	if _, err := rand.Read(token[:]); err != nil {
		return [2]byte{}, [4]byte{}, fmt.Errorf("generate token: %w", err)
	}
	if _, err := rand.Read(sessionID[:]); err != nil {
		return [2]byte{}, [4]byte{}, fmt.Errorf("generate session id: %w", err)
	}
	return token, sessionID, nil
}

func ipv4Destination(payload []byte) (netip.Addr, bool) {
	if len(payload) < 20 || payload[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	ihl := int(payload[0]&0x0f) * 4
	if ihl < 20 || len(payload) < ihl {
		return netip.Addr{}, false
	}
	var destination [4]byte
	copy(destination[:], payload[16:20])
	return netip.AddrFrom4(destination), true
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	clone := *addr
	if addr.IP != nil {
		clone.IP = append(net.IP(nil), addr.IP...)
	}
	return &clone
}
