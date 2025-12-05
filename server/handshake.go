package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"innerfade/common"
	"innerfade/common/cache"
	"innerfade/logger"

	utls "github.com/refraction-networking/utls"
)

func (s *Server) handleCustomProtocol(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(HandshakeTimeout))

	targetAddr, clientALPNs, err := s.readHandshake(conn)
	if err != nil {
		logger.Warnf("[%s] handshake parsing failed: %v", conn.RemoteAddr(), err)
		return
	}
	hostname, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		logger.Errorf("[%s] failed to parse address %s: %v", conn.RemoteAddr(), targetAddr, err)
		return
	}

	_, err = domainCache.Set(context.Background(), hostname)
	if err != nil {
		logger.Error(err)
	}

	destConn, negotiatedProto, err := s.dialTarget(targetAddr, clientALPNs)
	if err != nil {
		logger.Warnf("[%s] connection to target %s failed: %v", conn.RemoteAddr(), targetAddr, err)
		s.sendNegotiationResponse(conn, false, "")
		return
	}
	defer destConn.Close()

	logger.Infof("[%s] handling HTTPS request for %s (ALPN: %s)", conn.RemoteAddr(), targetAddr, negotiatedProto)

	err = s.sendNegotiationResponse(conn, true, negotiatedProto)
	if err != nil {
		logger.Error(err)
		return
	}

	conn.SetDeadline(time.Time{})
	common.TransferData(conn, destConn)
}

func (s *Server) readHandshake(conn net.Conn) (string, []string, error) {
	lenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return "", nil, err
	}
	domainLen := int(lenBuf[0])
	if domainLen == 0 {
		return "", nil, errors.New("empty domain length")
	}

	domainBuf := make([]byte, domainLen)
	if _, err := io.ReadFull(conn, domainBuf); err != nil {
		return "", nil, err
	}
	hostname := string(domainBuf)

	if !cache.IsValidDomain(hostname) {
		return "", nil, fmt.Errorf("[%s] invalid domain in handshake: %s", conn.RemoteAddr(), hostname)
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", nil, err
	}
	port := int(binary.BigEndian.Uint16(portBuf))
	targetAddr := fmt.Sprintf("%s:%d", hostname, port)

	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return "", nil, err
	}
	alpnCode := lenBuf[0]
	clientALPNs, ok := common.ByteToAlpn(alpnCode)
	if !ok {
		return "", nil, fmt.Errorf("[%s] failed to parse ALPN in handshake", conn.RemoteAddr())
	}
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", nil, err
	}
	paddingLen := int(binary.BigEndian.Uint16(portBuf))

	if paddingLen > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(paddingLen)); err != nil {
			return "", nil, fmt.Errorf("read padding failed: %w", err)
		}
	}

	return targetAddr, clientALPNs, nil
}

func (s *Server) sendNegotiationResponse(conn net.Conn, success bool, alpn string) error {
	buf := make([]byte, 0, 350)

	if !success {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	alpnCode, _ := common.AlpnToByte([]string{alpn})
	buf = append(buf, alpnCode)

	minTarget, maxTarget := 150, 350
	currentSize := len(buf) + 2
	paddingLen := 0

	if currentSize < minTarget {
		diff := minTarget - currentSize
		paddingLen = diff + secureRandomInt(maxTarget-minTarget)
		if currentSize+paddingLen > maxTarget {
			paddingLen = maxTarget - currentSize
		}
	} else if currentSize < maxTarget {
		paddingLen = secureRandomInt(maxTarget - currentSize)
	}

	padLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(padLenBytes, uint16(paddingLen))
	buf = append(buf, padLenBytes...)
	buf = append(buf, make([]byte, paddingLen)...)

	_, err := conn.Write(buf)
	return err
}

func (s *Server) dialTarget(address string, alpns []string) (net.Conn, string, error) {
	logger.Debugf("dialing target: %s with ALPNs: %v", address, alpns)
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if !cache.IsValidDomain(host) {
		return nil, "", fmt.Errorf("invalid domain for target dial: %s", host)
	}
	tlsConfig := &utls.Config{
		ServerName: host,
		NextProtos: alpns,
	}
	var conn net.Conn
	if s.config.Socks5Proxy != "" {
		conn, err = s.proxyDialer.Dial("tcp", address)
	} else {
		conn, err = net.Dial("tcp", address)
	}
	if err != nil {
		return nil, "", err
	}
	tlsConn := utls.UClient(conn, tlsConfig, utls.HelloChrome_Auto)
	if err = tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, "", err
	}
	return tlsConn, tlsConn.ConnectionState().NegotiatedProtocol, nil
}
