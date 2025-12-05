package reality

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/juju/ratelimit"
	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type CloseWriteConn interface {
	net.Conn
	CloseWrite() error
}

type MirrorConn struct {
	*sync.Mutex
	net.Conn
	Target net.Conn
}

func (c *MirrorConn) Read(b []byte) (int, error) {
	c.Unlock()
	runtime.Gosched()
	n, err := c.Conn.Read(b)
	c.Lock()
	if n != 0 {
		c.Target.Write(b[:n])
	}
	if err != nil {
		c.Target.Close()
	}
	return n, err
}

func (c *MirrorConn) Write(b []byte) (int, error) {
	return 0, fmt.Errorf("Write(%v)", len(b))
}

func (c *MirrorConn) Close() error {
	return fmt.Errorf("Close()")
}

func (c *MirrorConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *MirrorConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *MirrorConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type RatelimitedConn struct {
	net.Conn
	After  int64
	Bucket *ratelimit.Bucket
}

func (c *RatelimitedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n != 0 {
		if c.After > 0 {
			c.After -= int64(n)
		} else {
			c.Bucket.Wait(int64(n))
		}
	}
	return n, err
}

func NewRatelimitedConn(conn net.Conn, limit *LimitFallback) net.Conn {
	if limit.BytesPerSec == 0 {
		return conn
	}

	burstBytesPerSec := limit.BurstBytesPerSec
	if burstBytesPerSec < limit.BytesPerSec {
		burstBytesPerSec = limit.BytesPerSec
	}

	return &RatelimitedConn{
		Conn:   conn,
		After:  int64(limit.AfterBytes),
		Bucket: ratelimit.NewBucketWithRate(float64(limit.BytesPerSec), int64(burstBytesPerSec)),
	}
}

var (
	size  = 8192
	empty = make([]byte, size)
	types = [7]string{
		"Server Hello",
		"Change Cipher Spec",
		"Encrypted Extensions",
		"Certificate",
		"Certificate Verify",
		"Finished",
		"New Session Ticket",
	}
)

func Value(vals ...byte) (value int) {
	for i, val := range vals {
		value |= int(val) << ((len(vals) - i - 1) * 8)
	}
	return
}

func Server(ctx context.Context, conn net.Conn, config *Config) (*Conn, error) {
	remoteAddr := conn.RemoteAddr().String()
	if config.Show {
		fmt.Printf("REALITY remoteAddr: %v\n", remoteAddr)
	}

	target, err := config.DialContext(ctx, config.Type, config.Dest)
	if err != nil {
		conn.Close()
		return nil, errors.New("REALITY: failed to dial dest: " + err.Error())
	}

	raw := conn
	if pc, ok := conn.(*proxyproto.Conn); ok {
		raw = pc.Raw()
	}
	underlying := raw.(CloseWriteConn)
	mutex := new(sync.Mutex)

	hs := serverHandshakeStateTLS13{
		c: &Conn{
			conn: &MirrorConn{
				Mutex:  mutex,
				Conn:   conn,
				Target: target,
			},
			config: config,
		},
		ctx: context.Background(),
	}

	copying := false

	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(2)

	go func() {
		for {
			mutex.Lock()
			hs.clientHello, err = hs.c.readClientHello(context.Background())
			if copying || err != nil || hs.c.vers != VersionTLS13 || !config.ServerNames[hs.clientHello.serverName] {
				break
			}
			var peerPub []byte
			for _, keyShare := range hs.clientHello.keyShares {
				if keyShare.group == X25519 && len(keyShare.data) == 32 {
					peerPub = keyShare.data
					break
				}
			}
			if peerPub == nil {
				for _, keyShare := range hs.clientHello.keyShares {
					if keyShare.group == X25519MLKEM768 && len(keyShare.data) == mlkem.EncapsulationKeySize768+32 {
						peerPub = keyShare.data[mlkem.EncapsulationKeySize768:]
						break
					}
				}
			}
			for peerPub != nil {
				if hs.c.AuthKey, err = curve25519.X25519(config.PrivateKey, peerPub); err != nil {
					break
				}
				if _, err = hkdf.New(sha256.New, hs.c.AuthKey, []byte("cbeeff335e29"), []byte("REALITY")).Read(hs.c.AuthKey); err != nil {
					break
				}
				block, _ := aes.NewCipher(hs.c.AuthKey)
				aead, _ := cipher.NewGCMWithTagSize(block, 12)
				if config.Show {
					fmt.Printf("REALITY remoteAddr: %v\ths.c.AuthKey[:16]: %v\tAEAD: %T\n", remoteAddr, hs.c.AuthKey[:16], aead)
				}
				ciphertext := make([]byte, 64)
				plainText := make([]byte, 64)
				copy(ciphertext[:32], hs.clientHello.sessionId)
				copy(ciphertext[32:], hs.clientHello.random)
				copy(hs.clientHello.sessionId, plainText)
				copy(hs.clientHello.random, plainText)
				if _, err = aead.Open(plainText[:0], []byte("e936915be949"), ciphertext, hs.clientHello.original); err != nil {
					break
				}
				copy(hs.clientHello.sessionId, ciphertext[:32])
				copy(hs.clientHello.random, ciphertext[32:])
				hs.c.ClientTime = time.Unix(int64(binary.BigEndian.Uint32(plainText[48:])), 0)
				if config.Show {
					fmt.Printf("REALITY remoteAddr: %v\ths.c.ClientTime: %v\n", remoteAddr, hs.c.ClientTime)
				}
				if config.MaxTimeDiff == 0 || time.Since(hs.c.ClientTime).Abs() <= config.MaxTimeDiff {
					hs.c.conn = conn
					if config.GetServerMetaDataForClient != nil {
						copy(config.ServerMetaData[:], config.GetServerMetaDataForClient(conn.RemoteAddr().String(), plainText[:48]))
					}
				}
				break
			}
			if config.Show {
				fmt.Printf("REALITY remoteAddr: %v\ths.c.conn == conn: %v\n", remoteAddr, hs.c.conn == conn)
			}
			break
		}
		mutex.Unlock()
		if hs.c.conn != conn {
			if config.Show && hs.clientHello != nil {
				fmt.Printf("REALITY remoteAddr: %v\tforwarded SNI: %v\n", remoteAddr, hs.clientHello.serverName)
			}
			_, err := io.Copy(target, NewRatelimitedConn(underlying, &config.LimitFallbackUpload))
			if err == nil {
				targetWriterCloser, ok := target.(CloseWriteConn)
				if ok {
					targetWriterCloser.CloseWrite()
				}
			} else {
				target.Close()
			}
		}
		waitGroup.Done()
	}()

	go func() {
		s2cSaved := make([]byte, 0, size)
		buf := make([]byte, size)
		handshakeLen := 0
	f:
		for {
			runtime.Gosched()
			n, err := target.Read(buf)
			if n == 0 {
				if err != nil {
					conn.Close()
					waitGroup.Done()
					return
				}
				continue
			}
			mutex.Lock()
			s2cSaved = append(s2cSaved, buf[:n]...)
			if hs.c.conn != conn {
				copying = true
				break
			}
			if len(s2cSaved) > size {
				break
			}
			for i, t := range types {
				if hs.c.out.handshakeLen[i] != 0 {
					continue
				}
				if i == 6 && len(s2cSaved) == 0 {
					break
				}
				if handshakeLen == 0 && len(s2cSaved) > recordHeaderLen {
					if Value(s2cSaved[1:3]...) != VersionTLS12 ||
						(i == 0 && (recordType(s2cSaved[0]) != recordTypeHandshake || s2cSaved[5] != typeServerHello)) ||
						(i == 1 && (recordType(s2cSaved[0]) != recordTypeChangeCipherSpec || s2cSaved[5] != 1)) ||
						(i > 1 && recordType(s2cSaved[0]) != recordTypeApplicationData) {
						break f
					}
					handshakeLen = recordHeaderLen + Value(s2cSaved[3:5]...)
				}
				if config.Show {
					fmt.Printf("REALITY remoteAddr: %v\tlen(s2cSaved): %v\t%v: %v\n", remoteAddr, len(s2cSaved), t, handshakeLen)
				}
				if handshakeLen > size {
					break f
				}
				if i == 1 && handshakeLen > 0 && handshakeLen != 6 {
					break f
				}
				if i == 2 && handshakeLen > 512 {
					hs.c.out.handshakeLen[i] = handshakeLen
					hs.c.out.handshakeBuf = buf[:0]
					break
				}
				if i == 6 && handshakeLen > 0 {
					hs.c.out.handshakeLen[i] = handshakeLen
					break
				}
				if handshakeLen == 0 || len(s2cSaved) < handshakeLen {
					mutex.Unlock()
					continue f
				}
				if i == 0 {
					hs.hello = new(serverHelloMsg)
					if !hs.hello.unmarshal(s2cSaved[recordHeaderLen:handshakeLen]) ||
						hs.hello.vers != VersionTLS12 || hs.hello.supportedVersion != VersionTLS13 ||
						cipherSuiteTLS13ByID(hs.hello.cipherSuite) == nil ||
						(!(hs.hello.serverShare.group == X25519 && len(hs.hello.serverShare.data) == 32) &&
							!(hs.hello.serverShare.group == X25519MLKEM768 && len(hs.hello.serverShare.data) == mlkem.CiphertextSize768+32)) {
						break f
					}
					block, _ := aes.NewCipher(hs.c.AuthKey)
					aead, _ := cipher.NewGCMWithTagSize(block, 12)
					aead.Seal(hs.hello.random[:0], []byte("c0bbe77b11a5"), config.ServerMetaData[:], nil)
				}
				hs.c.out.handshakeLen[i] = handshakeLen
				s2cSaved = s2cSaved[handshakeLen:]
				handshakeLen = 0
			}
			start := time.Now()
			err = hs.handshake()
			if config.Show {
				fmt.Printf("REALITY remoteAddr: %v\ths.handshake() err: %v\n", remoteAddr, err)
			}
			if err != nil {
				break
			}
			go func() {
				if handshakeLen-len(s2cSaved) > 0 {
					io.ReadFull(target, buf[:handshakeLen-len(s2cSaved)])
				}
				if n, err := target.Read(buf); !hs.c.isHandshakeComplete.Load() {
					if err != nil {
						conn.Close()
					}
					if config.Show {
						fmt.Printf("REALITY remoteAddr: %v\ttime.Since(start): %v\tn: %v\terr: %v\n", remoteAddr, time.Since(start), n, err)
					}
				}
			}()
			err = hs.readClientFinished()
			if config.Show {
				fmt.Printf("REALITY remoteAddr: %v\ths.readClientFinished() err: %v\n", remoteAddr, err)
			}
			if err != nil {
				break
			}
			for {
				key := config.Dest + " " + hs.clientHello.serverName
				if len(hs.clientHello.alpnProtocols) == 0 {
					key += " 0"
				} else if hs.clientHello.alpnProtocols[0] == "h2" {
					key += " 2"
				} else {
					key += " 1"
				}
				if val, ok := GlobalPostHandshakeRecordsLens.Load(key); ok {
					if postHandshakeRecordsLens, ok := val.([]int); ok {
						for _, length := range postHandshakeRecordsLens {
							plainText := make([]byte, length-16)
							plainText[0] = 23
							plainText[1] = 3
							plainText[2] = 3
							plainText[3] = byte((length - 5) >> 8)
							plainText[4] = byte((length - 5))
							plainText[5] = 23
							postHandshakeRecord := hs.c.out.cipher.(aead).Seal(plainText[:5], hs.c.out.seq[:], plainText[5:], plainText[:5])
							hs.c.out.incSeq()
							hs.c.write(postHandshakeRecord)
							if config.Show {
								fmt.Printf("REALITY remoteAddr: %v\tlen(postHandshakeRecord): %v\n", remoteAddr, len(postHandshakeRecord))
							}
						}
						break
					}
				}
				time.Sleep(5 * time.Second)
			}
			hs.c.isHandshakeComplete.Store(true)
			break
		}
		mutex.Unlock()
		if hs.c.out.handshakeLen[0] == 0 {
			if hs.c.conn == conn {
				waitGroup.Add(1)
				go func() {
					io.Copy(target, NewRatelimitedConn(underlying, &config.LimitFallbackUpload))
					waitGroup.Done()
				}()
			}
			conn.Write(s2cSaved)
			io.Copy(underlying, NewRatelimitedConn(target, &config.LimitFallbackDownload))
			underlying.CloseWrite()
		}
		waitGroup.Done()
	}()

	waitGroup.Wait()
	target.Close()
	if config.Show {
		fmt.Printf("REALITY remoteAddr: %v\ths.c.isHandshakeComplete.Load(): %v\n", remoteAddr, hs.c.isHandshakeComplete.Load())
	}
	if hs.c.isHandshakeComplete.Load() {
		return hs.c, nil
	}

	conn.Close()
	var failureReason string
	if hs.clientHello == nil {
		failureReason = "failed to read client hello"
	} else if hs.c.vers != VersionTLS13 {
		failureReason = fmt.Sprintf("unsupported TLS version: %x", hs.c.vers)
	} else if !config.ServerNames[hs.clientHello.serverName] {
		failureReason = fmt.Sprintf("server name mismatch: %s", hs.clientHello.serverName)
	} else if hs.c.conn != conn {
		failureReason = "authentication failed or validation criteria not met"
	} else if hs.c.out.handshakeLen[0] == 0 {
		failureReason = "target sent incorrect server hello or handshake incomplete"
	} else {
		failureReason = "handshake did not complete successfully"
	}
	return nil, fmt.Errorf("REALITY: processed invalid connection from %s: %s", remoteAddr, failureReason)
}

type listener struct {
	net.Listener
	config *Config
	conns  chan net.Conn
	err    error
}

func (l *listener) Accept() (net.Conn, error) {
	if c, ok := <-l.conns; ok {
		return c, nil
	}
	return nil, l.err
}

func NewListener(inner net.Listener, config *Config) net.Listener {
	go DetectPostHandshakeRecordsLens(config)
	l := new(listener)
	l.Listener = inner
	l.config = config
	{
		l.conns = make(chan net.Conn)
		go func() {
			for {
				c, err := l.Listener.Accept()
				if err != nil {
					l.err = err
					close(l.conns)
					return
				}
				go func() {
					defer func() { recover() }()
					c, err = Server(context.Background(), c, l.config)
					if err == nil {
						l.conns <- c
					}
				}()
			}
		}()
	}
	return l
}

func Listen(network, laddr string, config *Config) (net.Listener, error) {
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}
