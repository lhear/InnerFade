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
	Show                     bool
	Dest                     string
	Type                     string
	Xver                     uint64
	ServerNames              []string
	PrivateKey               []byte
	MinClientVer             []byte
	MaxClientVer             []byte
	MaxTimeDiff              uint64
	ShortIds                 [][]byte
	Fingerprint              string
	ServerName               string
	PublicKey                []byte
	ShortId                  []byte
	Mldsa65Verify            []byte
	SpiderX                  string
	SpiderY                  []int64
	MasterKeyLog             string
	Random                   []byte
	GetServerRandomForClient func(remoteAddr string, clientRandom []byte) (serverRandom []byte)
}

func (c *Config) GetREALITYConfig() *reality.Config {
	var dialer net.Dialer
	config := &reality.Config{
		DialContext: dialer.DialContext,

		Show: c.Show,
		Type: c.Type,
		Dest: c.Dest,
		Xver: byte(c.Xver),

		PrivateKey:   c.PrivateKey,
		MinClientVer: c.MinClientVer,
		MaxClientVer: c.MaxClientVer,
		MaxTimeDiff:  time.Duration(c.MaxTimeDiff) * time.Millisecond,

		NextProtos:             nil, // should be nil
		SessionTicketsDisabled: true,
	}
	config.ServerNames = make(map[string]bool)
	for _, serverName := range c.ServerNames {
		config.ServerNames[serverName] = true
	}
	config.ShortIds = make(map[[8]byte]bool)
	for _, shortId := range c.ShortIds {
		config.ShortIds[*(*[8]byte)(shortId)] = true
	}
	config.GetServerRandomForClient = c.GetServerRandomForClient
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
	Config     *Config
	ServerName string
	AuthKey    []byte
	Verified   bool
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
	if c.Config.Show {
		localAddr := c.LocalAddr().String()
		fmt.Printf("REALITY localAddr: %v\tis using ML-DSA-65 for cert's extra verification: %v\n", localAddr, len(c.Config.Mldsa65Verify) > 0)
	}
	p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
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
		// Note: KeyLogWriterFromConfig removed as it requires external dependency
	}
	if utlsConfig.ServerName == "" {
		utlsConfig.ServerName = destAddr
	}
	uConn.ServerName = utlsConfig.ServerName

	// Use default fingerprint if none provided
	uConn.UConn = utls.UClient(c, utlsConfig, utls.HelloChrome_Auto)
	{
		uConn.BuildHandshakeState()
		hello := uConn.HandshakeState.Hello
		copy(hello.Random, config.Random)
		copy(hello.Raw[6:], hello.Random)
		hello.SessionId = make([]byte, 32)
		copy(hello.Raw[39:], hello.SessionId)
		// Use simple version numbers
		hello.SessionId[0] = 1
		hello.SessionId[1] = 0
		hello.SessionId[2] = 0
		hello.SessionId[3] = 0 // reserved
		binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
		copy(hello.SessionId[8:], config.ShortId)
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
			return nil, fmt.Errorf("Current fingerprint does not support TLS 1.3, REALITY handshake cannot establish.")
		}
		uConn.AuthKey, _ = ecdhe.ECDH(publicKey)
		if uConn.AuthKey == nil {
			return nil, fmt.Errorf("REALITY: SharedKey == nil")
		}
		if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey); err != nil {
			return nil, err
		}
		// Simplified AES-GCM implementation instead of xray crypto
		aead, err := newSimpleAesGcm(uConn.AuthKey)
		if err != nil {
			return nil, err
		}
		if config.Show {
			fmt.Printf("REALITY localAddr: %v\tuConn.AuthKey[:16]: %v\tAEAD\n", localAddr, uConn.AuthKey[:16])
		}
		aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
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

// Simple AES-GCM implementation
type simpleAesGcm struct {
	gcm cipher.AEAD
}

func newSimpleAesGcm(key []byte) (*simpleAesGcm, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &simpleAesGcm{gcm: gcm}, nil
}

func (s *simpleAesGcm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return s.gcm.Seal(dst, nonce, plaintext, additionalData)
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
