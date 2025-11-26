package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"innerfade/common"
	"innerfade/common/cache"
	"innerfade/common/crypto"
	"innerfade/logger"
)

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func (s *Server) acceptConnection(conn net.Conn) {

	if val, loaded := s.handshakeCache.LoadAndDelete(conn.RemoteAddr().String()); loaded {
		dest := val.(*Dest)
		if dest != nil {
			logger.Debugf("[%s] using pre-connection channel to %s:%d (ALPN: %s)", conn.RemoteAddr(), dest.host, dest.port, dest.alpn)
			common.TransferData(conn, dest.conn)
			return
		}
	}

	s.handleConnection(conn)
}

func (s *Server) handleClientRandom(remoteAddr string, clientRandom []byte) (serverRandom []byte) {

	serverRandom = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		return nil
	}

	var random32 [32]byte
	copy(random32[:], clientRandom)

	id, port, alpnCode, ok := cache.DecodeRandom(random32, s.encryptionKey)
	logger.Debugf("[%s] decoded client random - ID: %d, Port: %d, ALPN Code: 0x%x", remoteAddr, id, port, alpnCode)
	if !ok {
		return
	}

	domain, found, err := domainCache.Get(context.Background(), id)
	if err != nil {
		logger.Error(err)
		return
	}
	if !found {
		logger.Debugf("[%s] domain %s not found in cache, sending server cache miss status", remoteAddr, domain)
		serverRandom[0] = 2
		s.signServerRandom(serverRandom)
		return
	}

	targetAlpn, _ := common.ByteToAlpn(alpnCode)
	targetAddr := fmt.Sprintf("%s:%d", domain, port)

	destConn, negotiatedProto, err := s.dialTarget(targetAddr, targetAlpn)
	if err != nil {
		logger.Warnf("[%s] connection to target %s failed: %v", remoteAddr, targetAddr, err)
		serverRandom[0] = 1
		s.signServerRandom(serverRandom)
		return
	}

	logger.Infof("[%s] handling HTTPS request for %s (ALPN: %s)", remoteAddr, targetAddr, negotiatedProto)

	dest := &Dest{
		conn: destConn,
		host: domain,
		port: port,
		alpn: negotiatedProto,
	}

	s.handshakeCache.Store(remoteAddr, dest)

	respAlpnCode, _ := common.AlpnToByte([]string{negotiatedProto})
	serverRandom[0] = 0
	serverRandom[1] = respAlpnCode
	s.signServerRandom(serverRandom)

	return serverRandom
}

func (s *Server) signServerRandom(random []byte) {
	hash := sha256.Sum256(random[0:2])
	copy(random[2:10], hash[0:8])
	encryptedData, err := crypto.AESEncryptWithNonce(random[0:10], s.encryptionKey, random[10:32])
	if err != nil {
		return
	}
	copy(random[0:10], encryptedData)
}

func (s *Server) handleConnection(conn net.Conn) {
	peekBuf := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	n, err := conn.Read(peekBuf)
	conn.SetReadDeadline(time.Time{})

	if err != nil && !errors.Is(err, io.EOF) {
		return
	}

	peekedConn := &common.PeekedConn{
		Conn:        conn,
		InitialData: peekBuf[:n],
	}

	if isHTTPMethod(string(peekBuf[:n])) {
		s.handleHTTPRequest(peekedConn)
	} else {
		s.handleCustomProtocol(peekedConn)
	}
}

type Dest struct {
	conn net.Conn
	host string
	port uint16
	alpn string
}

func secureRandomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func (s *Server) handleHTTPRequest(conn net.Conn) {
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		logger.Warnf("[%s] failed to read HTTP request: %v", conn.RemoteAddr(), err)
		return
	}
	targetHost := req.Host
	if targetHost == "" {
		targetHost = req.URL.Host
	}
	if targetHost == "" {
		return
	}
	if !strings.Contains(targetHost, ":") {
		targetHost += ":80"
	}

	hostname, _, err := net.SplitHostPort(targetHost)
	if err != nil {
		hostname = targetHost
	}

	if !cache.IsValidDomain(hostname) {
		logger.Debugf("[%s] invalid domain rejected in HTTP request: %s", conn.RemoteAddr(), hostname)
		return
	}
	logger.Infof("[%s] handling HTTP request for %s", conn.RemoteAddr(), targetHost)
	var destConn net.Conn
	if s.config.Socks5Proxy != "" {
		destConn, err = s.proxyDialer.Dial("tcp", targetHost)
	} else {
		destConn, err = s.dialer.Dial("tcp", targetHost)
	}
	if err != nil {
		logger.Warnf("[%s] http proxy connection failed to %s: %v", conn.RemoteAddr(), targetHost, err)
		return
	}
	defer destConn.Close()

	req.RequestURI = ""
	delHopHeaders(req.Header)

	if err := req.Write(destConn); err != nil {
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(destConn), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	delHopHeaders(resp.Header)
	if err := resp.Write(conn); err != nil {
		return
	}
}

func isHTTPMethod(s string) bool {

	if len(s) < 3 {
		return false
	}
	method := strings.Split(s, " ")[0]
	switch method {
	case "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH":
		return true
	}
	return false
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}
