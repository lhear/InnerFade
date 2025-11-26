package client

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"innerfade/common"
	"innerfade/common/cache"
	"innerfade/common/crypto"
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
	serverConn, cacheUsed, err := c.dialUpstreamWithCache(hostname, uint16(port), browserALPNs)
	if err != nil {
		logger.Errorf("[%s] failed to connect to upstream server for %s: %v", r.RemoteAddr, hostname, err)
		return
	}
	defer serverConn.Close()

	var serverALPNs []string
	needHandshake := !cacheUsed

	if cacheUsed {
		serverRandom := serverConn.(*reality.UConn).HandshakeState.ServerHello.Random

		decryptedData, err := crypto.AESDecryptWithNonce(serverRandom[0:10], c.encryptionKey, serverRandom[10:32])
		if err != nil {
			needHandshake = true
		} else {
			expectedHash := decryptedData[2:10]
			calculatedHashFull := sha256.Sum256(decryptedData[0:2])
			calculatedHashTruncated := calculatedHashFull[0:8]

			if subtle.ConstantTimeCompare(calculatedHashTruncated, expectedHash) != 1 {
				logger.Errorf("[%s] server handshake validation failed for %s", r.RemoteAddr, hostname)
				return
			} else {

				switch decryptedData[0] {
				case 1:
					logger.Errorf("[%s] failed to connect to target server (server returned error) for %s", r.RemoteAddr, hostname)
					return
				case 2:
					logger.Debugf("[%s] server cache miss for %s, falling back to regular handshake", r.RemoteAddr, hostname)
					needHandshake = true
				case 0:

					alpn, ok := common.ByteToAlpn(decryptedData[1])
					if !ok {
						logger.Errorf("[%s] failed to parse target ALPN for %s", r.RemoteAddr, hostname)
						return
					} else {
						serverALPNs = alpn
					}
				default:
					logger.Errorf("[%s] unknown status code %d for %s", r.RemoteAddr, decryptedData[0], hostname)
					return
				}
			}
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

	serverConn, err := c.dialUpstream(nil)
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
