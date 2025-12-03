package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"

	reality "innerfade/common/reality/server"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

type Conn struct {
	*reality.Conn
}

type Config struct {
	Show                       bool
	Dest                       string
	Type                       string
	ServerNames                []string
	PrivateKey                 []byte
	MaxTimeDiff                uint64
	Fingerprint                utls.ClientHelloID
	ServerName                 string
	PublicKey                  []byte
	SpiderX                    string
	SpiderY                    []int64
	MasterKeyLog               string
	ClientMetaData             [48]byte
	ServerMetaData             [12]byte
	GetServerMetaDataForClient func(remoteAddr string, data []byte) []byte
}

func (c *Config) GetREALITYConfig() *reality.Config {
	var dialer net.Dialer
	config := &reality.Config{
		DialContext:                 dialer.DialContext,
		Show:                        c.Show,
		Type:                        c.Type,
		Dest:                        c.Dest,
		PrivateKey:                  c.PrivateKey,
		MaxTimeDiff:                 time.Duration(c.MaxTimeDiff) * time.Millisecond,
		NextProtos:                  nil,
		SessionTicketsDisabled:      true,
		DynamicRecordSizingDisabled: true,
	}
	config.ServerNames = make(map[string]bool)
	for _, serverName := range c.ServerNames {
		config.ServerNames[serverName] = true
	}
	config.GetServerMetaDataForClient = c.GetServerMetaDataForClient
	return config
}

func (c *Conn) HandshakeAddress() net.Addr {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	addr, err := net.ResolveTCPAddr("tcp", state.ServerName+":443")
	if err != nil {
		return nil
	}
	return addr
}

func Server(c net.Conn, config *Config) (net.Conn, error) {
	conf := config.GetREALITYConfig()
	reality.DetectPostHandshakeRecordsLens(conf)
	realityConn, err := reality.Server(context.Background(), c, conf)
	return &Conn{Conn: realityConn}, err
}

type UConn struct {
	*utls.UConn
	Config         *Config
	ServerName     string
	AuthKey        []byte
	Verified       bool
	ServerMetaData [12]byte
}

func (c *UConn) HandshakeAddress() net.Addr {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	addr, err := net.ResolveTCPAddr("tcp", state.ServerName+":443")
	if err != nil {
		return nil
	}
	return addr
}

func (c *UConn) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			aead, err := newSimpleAesGcm(c.AuthKey)
			if err != nil {
				return err
			}
			_, err = aead.Open(c.ServerMetaData[:0], []byte("c0bbe77b11a5"), c.HandshakeState.ServerHello.Random[:24], nil)
			if err != nil {
				return err
			}
			c.Verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

func UClient(c net.Conn, config *Config, ctx context.Context, destAddr string) (net.Conn, error) {
	localAddr := c.LocalAddr().String()
	uConn := &UConn{
		Config: config,
	}
	utlsConfig := &utls.Config{
		VerifyPeerCertificate:  uConn.VerifyPeerCertificate,
		ServerName:             config.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}
	if utlsConfig.ServerName == "" {
		utlsConfig.ServerName = destAddr
	}
	uConn.ServerName = utlsConfig.ServerName

	// Use default fingerprint if none provided
	uConn.UConn = utls.UClient(c, utlsConfig, config.Fingerprint)
	{
		uConn.BuildHandshakeState()
		hello := uConn.HandshakeState.Hello
		hello.SessionId = make([]byte, 32)
		copy(hello.Raw[39:], hello.SessionId)
		copy(hello.Raw[6:], hello.SessionId)
		copy(hello.SessionId, config.ClientMetaData[:32])
		copy(hello.Random, config.ClientMetaData[32:])
		binary.BigEndian.PutUint32(hello.Random[16:], uint32(time.Now().Unix()))
		if config.Show {
			fmt.Printf("REALITY localAddr: %v\thello.SessionId[:16]: %v\n", localAddr, hello.SessionId[:16])
		}
		publicKey, err := ecdh.X25519().NewPublicKey(config.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("REALITY: publicKey == nil: %v", err)
		}
		ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
		if ecdhe == nil {
			ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
		}
		if ecdhe == nil {
			return nil, fmt.Errorf("current fingerprint does not support TLS 1.3, REALITY handshake cannot establish")
		}
		uConn.AuthKey, _ = ecdhe.ECDH(publicKey)
		if uConn.AuthKey == nil {
			return nil, fmt.Errorf("REALITY: SharedKey == nil")
		}
		if _, err := hkdf.New(sha256.New, uConn.AuthKey, []byte("cbeeff335e29"), []byte("REALITY")).Read(uConn.AuthKey); err != nil {
			return nil, err
		}
		aead, err := newSimpleAesGcm(uConn.AuthKey)
		if err != nil {
			return nil, err
		}
		if config.Show {
			fmt.Printf("REALITY localAddr: %v\tuConn.AuthKey[:16]: %v\tAEAD\n", localAddr, uConn.AuthKey[:16])
		}
		buf := make([]byte, 64)
		copy(buf[:32], hello.SessionId)
		copy(buf[32:], hello.Random)
		aead.Seal(buf[:0], []byte("e936915be949"), buf[:52], hello.Raw)
		copy(hello.SessionId, buf[:32])
		copy(hello.Raw[39:], hello.SessionId)
		copy(hello.Random, buf[32:])
		copy(hello.Raw[6:], hello.Random)
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if config.Show {
		fmt.Printf("REALITY localAddr: %v\tuConn.Verified: %v\n", localAddr, uConn.Verified)
	}
	if !uConn.Verified {
		go func() {
			client := &http.Client{
				Transport: &http2.Transport{
					DialTLSContext: func(ctx context.Context, network, addr string, cfg *gotls.Config) (net.Conn, error) {
						fmt.Printf("REALITY localAddr: %v\tDialTLSContext\n", localAddr)
						return uConn, nil
					},
				},
			}
			prefix := []byte("https://" + uConn.ServerName)
			maps.Lock()
			if maps.maps == nil {
				maps.maps = make(map[string]map[string]struct{})
			}
			paths := maps.maps[uConn.ServerName]
			if paths == nil {
				paths = make(map[string]struct{})
				paths[config.SpiderX] = struct{}{}
				maps.maps[uConn.ServerName] = paths
			}
			firstURL := string(prefix) + getPathLocked(paths)
			maps.Unlock()
			get := func(first bool) {
				var (
					req  *http.Request
					resp *http.Response
					err  error
					body []byte
				)
				if first {
					req, _ = http.NewRequest("GET", firstURL, nil)
				} else {
					maps.Lock()
					req, _ = http.NewRequest("GET", string(prefix)+getPathLocked(paths), nil)
					maps.Unlock()
				}
				if req == nil {
					return
				}
				// Use a simple user agent instead of fingerprint.Client
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36") // TODO: User-Agent map
				if first && config.Show {
					fmt.Printf("REALITY localAddr: %v\treq.UserAgent(): %v\n", localAddr, req.UserAgent())
				}
				times := 1
				if !first {
					// Simplified random times - using basic math/rand instead of xray crypto
					times = 3 // Default value instead of crypto.RandBetween
				}
				for j := 0; j < times; j++ {
					if !first && j == 0 {
						req.Header.Set("Referer", firstURL)
					}
					// Use fixed padding instead of random padding
					req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", 32)})
					if resp, err = client.Do(req); err != nil {
						break
					}
					defer resp.Body.Close()
					req.Header.Set("Referer", req.URL.String())
					if body, err = io.ReadAll(resp.Body); err != nil {
						break
					}
					maps.Lock()
					for _, m := range href.FindAllSubmatch(body, -1) {
						m[1] = bytes.TrimPrefix(m[1], prefix)
						if !bytes.Contains(m[1], dot) {
							paths[string(m[1])] = struct{}{}
						}
					}
					req.URL.Path = getPathLocked(paths)
					if config.Show {
						fmt.Printf("REALITY localAddr: %v\treq.Referer(): %v\n", localAddr, req.Referer())
						fmt.Printf("REALITY localAddr: %v\tlen(body): %v\n", localAddr, len(body))
						fmt.Printf("REALITY localAddr: %v\tlen(paths): %v\n", localAddr, len(paths))
					}
					maps.Unlock()
					if !first {
						// Fixed sleep duration instead of random
						time.Sleep(100 * time.Millisecond) // interval
					}
				}
			}
			get(true)
			// Fixed concurrency instead of random
			concurrency := 2
			for i := 0; i < concurrency; i++ {
				go get(false)
			}
			// Do not close the connection
		}()
		// Fixed sleep duration instead of random
		time.Sleep(200 * time.Millisecond) // return
		return nil, fmt.Errorf("REALITY: processed invalid connection")
	}
	return uConn, nil
}

var (
	href = regexp.MustCompile(`href="([/h].*?)"`)
	dot  = []byte(".")
)

func newSimpleAesGcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithTagSize(block, 12)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

func getPathLocked(paths map[string]struct{}) string {
	count := 0
	for range paths {
		count++
	}
	if count == 0 {
		return "/"
	}

	stopAt := count / 2 // Simplified instead of random
	i := 0
	for s := range paths {
		if i == stopAt {
			return s
		}
		i++
	}
	return "/"
}

var maps struct {
	sync.Mutex
	maps map[string]map[string]struct{}
}

func ParseFingerprintStr(fingerprint string) (utls.ClientHelloID, error) {
	switch strings.ToLower(fingerprint) {
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "":
		return utls.HelloChrome_Auto, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unsupported uTLS fingerprint: %s", fingerprint)
	}
}
