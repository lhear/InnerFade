package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"innerfade/common"
	"innerfade/common/cache"
	"innerfade/common/compress"
	"innerfade/common/reality"
	"innerfade/logger"
)

func (c *Client) parseHost(hostPort string) (string, int, error) {
	if !strings.Contains(hostPort, ":") {
		hostPort += ":443"
	}
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		var pErr error
		port, pErr = net.LookupPort("tcp", portStr)
		if pErr != nil {
			return "", 0, pErr
		}
	}
	return host, port, nil
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

func (c *Client) dialUpstreamWithMetaData(hostname string, port uint16, alpn []string) (net.Conn, bool, error) {
	if !cache.IsValidDomain(hostname) {
		return nil, false, fmt.Errorf("invalid domain: %s", hostname)
	}

	alpnCode, ok := common.AlpnToByte(alpn)
	if !ok {
		return nil, false, fmt.Errorf("[%s] Unsupported ALPN, connection rejected", hostname)
	}

	if metaData, ok := EncodeMetaDataByDomain(hostname, port, alpnCode); ok {
		conn, err := c.dialUpstream(metaData)
		if err != nil {
			return conn, false, err
		}
		return conn, true, nil
	}

	id := cache.GenerateID(hostname)
	_, found, err := domainCache.Get(context.Background(), id)

	if err != nil {
		return nil, false, err
	}

	if !found {
		logger.Debugf("[%s] domain cache miss for %s, dialing directly.", hostname, hostname)
		conn, err := c.dialUpstream([44]byte{})
		if err == nil {
			_, err = domainCache.Set(context.Background(), hostname)
		}
		return conn, false, err
	}
	logger.Debugf("[%s] domain cache hit for %s", hostname, hostname)

	conn, err := c.dialUpstream(EncodeMetaDataById(id, port, alpnCode))
	if err != nil {
		return conn, false, err
	}

	return conn, true, nil
}

func (c *Client) dialUpstream(metaData [44]byte) (net.Conn, error) {
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
		Fingerprint: c.fingerprint,
		Show:        logger.IsDebugEnabled(),
	}

	copy(config.ClientMetaData[:], metaData[:])

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

func EncodeMetaDataByDomain(domainStr string, port uint16, alpnCode byte) ([44]byte, bool) {
	var data [44]byte
	domain, err := compress.Compress(domainStr)
	if err != nil {
		return data, false
	}
	domainLen := len(domain)
	if domainLen+5 > 44 {
		return data, false
	}
	logger.Debugf("Domain: %s | Compression Ratio: %.2f (Original: %d bytes, Compressed: %d bytes)",
		domainStr, float64(domainLen)/float64(len(domainStr)), len(domainStr), domainLen)
	data[0] = 2
	data[1] = byte(domainLen)
	copy(data[2:], domain)
	len := 2 + domainLen
	binary.BigEndian.PutUint16(data[len:len+2], port)
	len += 2
	data[len] = alpnCode
	return data, true
}

func EncodeMetaDataById(id [8]byte, port uint16, alpnCode byte) [44]byte {
	var data [44]byte
	data[0] = 1
	copy(data[1:9], id[:])
	binary.BigEndian.PutUint16(data[9:11], port)
	data[11] = alpnCode
	return data
}
