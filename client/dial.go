package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"innerfade/common"
	"innerfade/common/cache"
	"innerfade/common/reality"
	"innerfade/logger"
)

func (c *Client) parseHost(hostPort string) (string, int, error) {
	if !strings.Contains(hostPort, ":") {
		hostPort += ":443"
	}
	return common.ParseHostPort(hostPort)
}

func (c *Client) hijackConn(w http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("hijack unsupported")
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) dialUpstreamWithCache(hostname string, port uint16, alpn []string) (net.Conn, bool, error) {
	if !cache.IsValidDomain(hostname) {
		return nil, false, fmt.Errorf("invalid domain: %s", hostname)
	}

	id := cache.GenerateID(hostname)
	_, found, err := domainCache.Get(context.Background(), id)

	if err != nil {
		return nil, false, err
	}

	if !found {
		logger.Debugf("[%s] domain cache miss for %s, dialing directly.", hostname, hostname)
		conn, err := c.dialUpstream(nil)
		if err == nil {
			_, err = domainCache.Set(context.Background(), hostname)
		}
		return conn, false, err
	}
	logger.Debugf("[%s] domain cache hit for %s", hostname, hostname)
	alpnCode, ok := common.AlpnToByte(alpn)
	if !ok {
		return nil, false, fmt.Errorf("[%s] Unsupported ALPN, connection rejected", hostname)
	}

	random, err := cache.EncodeRandom(id, port, alpnCode, c.encryptionKey)
	if err != nil {
		conn, err := c.dialUpstream(nil)
		return conn, false, err
	}

	var customRandom [32]byte
	copy(customRandom[:], random[:])

	conn, err := c.dialUpstream(&customRandom)
	if err != nil {
		return conn, false, err
	}

	return conn, true, nil
}

func (c *Client) dialUpstream(customRandom *[32]byte) (net.Conn, error) {
	rawConn, err := c.dialer.Dial("tcp", c.serverAddr)
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(c.serverAddr)
	if host == "" {
		host = c.serverAddr
	}

	config := &reality.Config{
		ServerName:  c.config.ServerName,
		PublicKey:   c.publicKey,
		Fingerprint: "chrome",
		Show:        logger.IsDebugEnabled(),
	}

	if customRandom != nil {
		config.Random = customRandom[:]
	}

	conn, err := reality.UClient(rawConn, config, context.Background(), host)
	if err == nil {
		logger.Debugf("successfully dialed upstream server: %s", c.serverAddr)
	}

	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("REALITY handshake failed: %w", err)
	}

	return conn, nil
}
