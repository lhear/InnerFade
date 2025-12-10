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

type Config struct {
	Show                       bool
	Dest                       string
	ServerNames                []string
	PrivateKey                 []byte
	MaxTimeDiff                uint64
	Fingerprint                utls.ClientHelloID
	ServerName                 string
	PublicKey                  []byte
	SpiderX                    string
	GetServerMetaDataForClient func(remoteAddr string, data []byte) []byte
}

type Protocol struct {
	Config             *Config
	serverConfig       *reality.Config
	clientECDPublicKey *ecdh.PublicKey
}

func NewProtocol(c *Config) (*Protocol, error) {
	p := &Protocol{
		Config: c,
	}

	var dialer net.Dialer
	rConf := &reality.Config{
		DialContext:                 dialer.DialContext,
		Show:                        c.Show,
		Type:                        "tcp",
		Dest:                        c.Dest,
		PrivateKey:                  c.PrivateKey,
		MaxTimeDiff:                 time.Duration(c.MaxTimeDiff) * time.Millisecond,
		NextProtos:                  nil,
		SessionTicketsDisabled:      true,
		DynamicRecordSizingDisabled: true,
		ServerNames:                 make(map[string]bool, len(c.ServerNames)),
		GetServerMetaDataForClient:  c.GetServerMetaDataForClient,
	}
	for _, serverName := range c.ServerNames {
		rConf.ServerNames[serverName] = true
	}

	go reality.DetectPostHandshakeRecordsLens(rConf)
	p.serverConfig = rConf

	if len(c.PublicKey) > 0 {
		pubKey, err := ecdh.X25519().NewPublicKey(c.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("REALITY: invalid public key: %v", err)
		}
		p.clientECDPublicKey = pubKey
	}

	return p, nil
}

type Conn struct {
	*reality.Conn
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

func (p *Protocol) Server(c net.Conn) (net.Conn, error) {
	realityConn, err := reality.Server(context.Background(), c, p.serverConfig)
	return &Conn{Conn: realityConn}, err
}

type UConn struct {
	*utls.UConn
	Protocol       *Protocol
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

func (p *Protocol) UClient(c net.Conn, ctx context.Context, destAddr string, metadata [48]byte) (net.Conn, error) {
	localAddr := c.LocalAddr().String()
	uConn := &UConn{
		Protocol: p,
	}
	utlsConfig := &utls.Config{
		VerifyPeerCertificate:  uConn.VerifyPeerCertificate,
		ServerName:             p.Config.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}
	if utlsConfig.ServerName == "" {
		utlsConfig.ServerName = destAddr
	}
	uConn.ServerName = utlsConfig.ServerName

	uConn.UConn = utls.UClient(c, utlsConfig, p.Config.Fingerprint)
	{
		uConn.BuildHandshakeState()
		hello := uConn.HandshakeState.Hello
		hello.SessionId = make([]byte, 32)
		copy(hello.Raw[39:], hello.SessionId)
		copy(hello.Raw[6:], hello.SessionId)
		if p.Config.Show {
			fmt.Printf("REALITY localAddr: %v\thello.SessionId[:16]: %v\n", localAddr, hello.SessionId[:16])
		}
		if p.clientECDPublicKey == nil {
			return nil, fmt.Errorf("REALITY: publicKey is not initialized")
		}
		ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
		if ecdhe == nil {
			ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
		}
		if ecdhe == nil {
			return nil, fmt.Errorf("current fingerprint does not support TLS 1.3, REALITY handshake cannot establish")
		}
		uConn.AuthKey, _ = ecdhe.ECDH(p.clientECDPublicKey)
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
		if p.Config.Show {
			fmt.Printf("REALITY localAddr: %v\tuConn.AuthKey[:16]: %v\tAEAD\n", localAddr, uConn.AuthKey[:16])
		}
		buf := make([]byte, 64)
		copy(buf, metadata[:])
		binary.BigEndian.PutUint32(buf[48:], uint32(time.Now().Unix()))
		aead.Seal(buf[:0], []byte("e936915be949"), buf[:52], hello.Raw)
		copy(hello.SessionId, buf[:32])
		copy(hello.Raw[39:], hello.SessionId)
		copy(hello.Random, buf[32:])
		copy(hello.Raw[6:], hello.Random)
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if p.Config.Show {
		fmt.Printf("REALITY localAddr: %v\tuConn.Verified: %v\n", localAddr, uConn.Verified)
	}

	if !uConn.Verified {
		go runSpider(p, uConn, localAddr)
		time.Sleep(200 * time.Millisecond)
		return nil, fmt.Errorf("REALITY: processed invalid connection")
	}
	return uConn, nil
}

func runSpider(p *Protocol, uConn *UConn, localAddr string) {
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *gotls.Config) (net.Conn, error) {
				if p.Config.Show {
					fmt.Printf("REALITY localAddr: %v\tDialTLSContext\n", localAddr)
				}
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
		paths[p.Config.SpiderX] = struct{}{}
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
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		if first && p.Config.Show {
			fmt.Printf("REALITY localAddr: %v\treq.UserAgent(): %v\n", localAddr, req.UserAgent())
		}
		times := 1
		if !first {
			times = 3
		}
		for j := 0; j < times; j++ {
			if !first && j == 0 {
				req.Header.Set("Referer", firstURL)
			}
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
			if p.Config.Show {
				fmt.Printf("REALITY localAddr: %v\treq.Referer(): %v\n", localAddr, req.Referer())
				fmt.Printf("REALITY localAddr: %v\tlen(body): %v\n", localAddr, len(body))
				fmt.Printf("REALITY localAddr: %v\tlen(paths): %v\n", localAddr, len(paths))
			}
			maps.Unlock()
			if !first {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	get(true)
	concurrency := 2
	for range concurrency {
		go get(false)
	}
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

	stopAt := count / 2
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
