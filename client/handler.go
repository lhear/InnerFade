package client

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"innerfade/common"
	"innerfade/common/cache"
	"innerfade/common/reality"
	"innerfade/logger"
)

func (c *Client) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		c.handleConnect(w, r)
	} else {
		c.handleHTTP(w, r)
	}
}

func (c *Client) handleConnect(w http.ResponseWriter, r *http.Request) {
	_, port, err := c.parseHost(r.Host)
	if err != nil {
		http.Error(w, "Invalid Host", http.StatusBadRequest)
		return
	}

	clientConn, err := c.hijackConn(w)
	if err != nil {
		logger.Errorf("[%s] hijack failed for %s: %v", r.RemoteAddr, r.Host, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	peekedConn, sni, browserALPNs, err := c.peekClientHello(clientConn)
	if err != nil || sni == "" || browserALPNs == nil {
		logger.Errorf("[%s] failed to read TLS ClientHello for %s: %v", r.RemoteAddr, r.Host, err)
		return
	}
	hostname := sni
	if !cache.IsValidDomain(hostname) {
		logger.Debugf("[%s] invalid SNI domain rejected: %s", r.RemoteAddr, hostname)
		return
	}
	logger.Infof("[%s] handling HTTPS request for %s:%d", r.RemoteAddr, hostname, port)
	serverConn, metaDataUsed, err := c.dialUpstreamWithMetaData(hostname, uint16(port), browserALPNs)
	if err != nil {
		logger.Errorf("[%s] failed to connect to upstream server for %s: %v", r.RemoteAddr, hostname, err)
		return
	}
	defer serverConn.Close()

	var serverALPNs []string
	needHandshake := !metaDataUsed

	if metaDataUsed {
		serverMetaData := serverConn.(*reality.UConn).ServerMetaData

		switch serverMetaData[0] {
		case 1:
			logger.Errorf("[%s] failed to connect to target server (server returned error) for %s", r.RemoteAddr, hostname)
			return
		case 2:
			logger.Debugf("[%s] server cache miss for %s, falling back to regular handshake", r.RemoteAddr, hostname)
			needHandshake = true
		case 0:
			alpn, ok := common.ByteToAlpn(serverMetaData[1])
			if !ok {
				logger.Errorf("[%s] failed to parse target ALPN for %s", r.RemoteAddr, hostname)
				return
			} else {
				serverALPNs = alpn
			}
		default:
			logger.Errorf("[%s] unknown status code %d for %s", r.RemoteAddr, serverMetaData[0], hostname)
			return
		}
	}

	if needHandshake {
		serverALPNs, err = c.handshakeServer(serverConn, hostname, port, browserALPNs)
		if err != nil {
			logger.Errorf("[%s] handshake failed for %s: %v", r.RemoteAddr, hostname, err)
			return
		}
	}
	logger.Infof("[%s] negotiated ALPN: %v", r.RemoteAddr, serverALPNs)

	tlsConfig := c.createTLSConfigWithALPNs(hostname, serverALPNs)
	tlsConn := tls.Server(peekedConn, tlsConfig)

	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {

		if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "user canceled") {
			logger.Debugf("[%s] browser TLS handshake failed for %s: %v", r.RemoteAddr, hostname, err)
		}
		return
	}
	tlsConn.SetDeadline(time.Time{})
	common.TransferData(tlsConn, serverConn)
}

func (c *Client) handleHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infof("[%s] handling HTTP request for %s", r.RemoteAddr, r.Host)
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	r.RequestURI = ""

	serverConn, err := c.dialUpstream([48]byte{})
	if err != nil {
		logger.Errorf("[%s] HTTP proxy connection failed to %s: %v", r.RemoteAddr, r.URL.String(), err)
		http.Error(w, "proxy connection failed", http.StatusBadGateway)
		return
	}
	defer serverConn.Close()

	if err := r.Write(serverConn); err != nil {
		logger.Errorf("[%s] HTTP write request failed to %s: %v", r.RemoteAddr, r.URL.String(), err)
		http.Error(w, "write request failed", http.StatusInternalServerError)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(serverConn), r)
	if err != nil {
		logger.Errorf("[%s] HTTP read response failed from %s: %v", r.RemoteAddr, r.URL.String(), err)
		http.Error(w, "read response failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
