package reality

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"innerfade/common/reality/server/fips140tls"
	"io"
	"net"
	"slices"
	"sync"
	"time"
	_ "unsafe"
)

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304

	VersionSSL30 = 0x0300
)

func VersionName(version uint16) string {
	switch version {
	case VersionSSL30:
		return "SSLv3"
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}

const (
	maxPlaintext               = 16384
	maxCiphertext              = 16384 + 2048
	maxCiphertextTLS13         = 16384 + 256
	recordHeaderLen            = 5
	maxHandshake               = 65536
	maxHandshakeCertificateMsg = 262144
	maxUselessRecords          = 16
)

type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
)

const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionExtendedMasterSecret    uint16 = 23
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionQUICTransportParameters uint16 = 57
	extensionRenegotiationInfo       uint16 = 0xff01
	extensionECHOuterExtensions      uint16 = 0xfd00
	extensionEncryptedClientHello    uint16 = 0xfe0d
)

const (
	scsvRenegotiation uint16 = 0x00ff
)

type CurveID uint16

const (
	CurveP256      CurveID = 23
	CurveP384      CurveID = 24
	CurveP521      CurveID = 25
	X25519         CurveID = 29
	X25519MLKEM768 CurveID = 4588
)

type keyShare struct {
	group CurveID
	data  []byte
}

const (
	pskModeDHE uint8 = 1
)

type pskIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}

const (
	statusTypeOCSP uint8 = 1
)

const (
	signaturePKCS1v15 uint8 = iota + 225
	signatureRSAPSS
	signatureECDSA
	signatureEd25519
)

var directSigning crypto.Hash = 0

type ConnectionState struct {
	Version uint16

	HandshakeComplete bool

	DidResume bool

	CipherSuite uint16

	CurveID CurveID

	NegotiatedProtocol string

	NegotiatedProtocolIsMutual bool

	ServerName string

	PeerCertificates []*x509.Certificate

	VerifiedChains [][]*x509.Certificate

	SignedCertificateTimestamps [][]byte

	OCSPResponse []byte

	TLSUnique []byte

	ECHAccepted bool

	ekm func(label string, context []byte, length int) ([]byte, error)

	testingOnlyDidHRR bool
}

type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

type ClientSessionCache interface {
	Get(sessionKey string) (session *ClientSessionState, ok bool)

	Put(sessionKey string, cs *ClientSessionState)
}

type SignatureScheme uint16

const (
	PKCS1WithSHA256 SignatureScheme = 0x0401
	PKCS1WithSHA384 SignatureScheme = 0x0501
	PKCS1WithSHA512 SignatureScheme = 0x0601

	PSSWithSHA256 SignatureScheme = 0x0804
	PSSWithSHA384 SignatureScheme = 0x0805
	PSSWithSHA512 SignatureScheme = 0x0806

	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603

	Ed25519 SignatureScheme = 0x0807

	PKCS1WithSHA1 SignatureScheme = 0x0201
	ECDSAWithSHA1 SignatureScheme = 0x0203
)

type ClientHelloInfo struct {
	CipherSuites []uint16

	ServerName string

	SupportedCurves []CurveID

	SupportedPoints []uint8

	SignatureSchemes []SignatureScheme

	SupportedProtos []string

	SupportedVersions []uint16

	Extensions []uint16

	Conn net.Conn

	config *Config

	ctx context.Context
}

func (c *ClientHelloInfo) Context() context.Context {
	return c.ctx
}

type RenegotiationSupport int

const (
	RenegotiateNever RenegotiationSupport = iota

	RenegotiateOnceAsClient

	RenegotiateFreelyAsClient
)

type LimitFallback struct {
	AfterBytes       uint64
	BytesPerSec      uint64
	BurstBytesPerSec uint64
}

type Config struct {
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)

	Show bool
	Type string
	Dest string

	ServerNames map[string]bool
	PrivateKey  []byte
	MaxTimeDiff time.Duration

	GetServerMetaDataForClient func(remoteAddr string, data []byte) []byte

	LimitFallbackUpload   LimitFallback
	LimitFallbackDownload LimitFallback

	Rand io.Reader

	Time func() time.Time

	Certificates []Certificate

	NameToCertificate map[string]*Certificate

	GetCertificate func(*ClientHelloInfo) (*Certificate, error)

	GetConfigForClient func(*ClientHelloInfo) (*Config, error)

	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	VerifyConnection func(ConnectionState) error

	RootCAs *x509.CertPool

	NextProtos []string

	ServerName string

	ClientAuth ClientAuthType

	ClientCAs *x509.CertPool

	InsecureSkipVerify bool

	CipherSuites []uint16

	PreferServerCipherSuites bool

	SessionTicketsDisabled bool

	SessionTicketKey [32]byte

	ClientSessionCache ClientSessionCache

	UnwrapSession func(identity []byte, cs ConnectionState) (*SessionState, error)

	WrapSession func(ConnectionState, *SessionState) ([]byte, error)

	MinVersion uint16

	MaxVersion uint16

	CurvePreferences []CurveID

	DynamicRecordSizingDisabled bool

	Renegotiation RenegotiationSupport

	KeyLogWriter io.Writer

	EncryptedClientHelloConfigList []byte

	EncryptedClientHelloRejectionVerify func(ConnectionState) error

	GetEncryptedClientHelloKeys func(*ClientHelloInfo) ([]EncryptedClientHelloKey, error)

	EncryptedClientHelloKeys []EncryptedClientHelloKey

	mutex                 sync.RWMutex
	sessionTicketKeys     []ticketKey
	autoSessionTicketKeys []ticketKey
}

type EncryptedClientHelloKey struct {
	Config      []byte
	PrivateKey  []byte
	SendAsRetry bool
}

const (
	ticketKeyLifetime = 7 * 24 * time.Hour
	ticketKeyRotation = 24 * time.Hour
)

type ticketKey struct {
	aesKey  [16]byte
	hmacKey [16]byte
	created time.Time
}

func (c *Config) ticketKeyFromBytes(b [32]byte) (key ticketKey) {
	hashed := sha512.Sum512(b[:])
	const legacyTicketKeyNameLen = 16
	copy(key.aesKey[:], hashed[legacyTicketKeyNameLen:])
	copy(key.hmacKey[:], hashed[legacyTicketKeyNameLen+len(key.aesKey):])
	key.created = c.time()
	return key
}

const maxSessionTicketLifetime = 7 * 24 * time.Hour

func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return &Config{
		DialContext:                         c.DialContext,
		Show:                                c.Show,
		Type:                                c.Type,
		Dest:                                c.Dest,
		ServerNames:                         c.ServerNames,
		PrivateKey:                          c.PrivateKey,
		MaxTimeDiff:                         c.MaxTimeDiff,
		LimitFallbackUpload:                 c.LimitFallbackUpload,
		LimitFallbackDownload:               c.LimitFallbackDownload,
		Rand:                                c.Rand,
		Time:                                c.Time,
		Certificates:                        c.Certificates,
		NameToCertificate:                   c.NameToCertificate,
		GetCertificate:                      c.GetCertificate,
		GetConfigForClient:                  c.GetConfigForClient,
		GetEncryptedClientHelloKeys:         c.GetEncryptedClientHelloKeys,
		VerifyPeerCertificate:               c.VerifyPeerCertificate,
		VerifyConnection:                    c.VerifyConnection,
		RootCAs:                             c.RootCAs,
		NextProtos:                          c.NextProtos,
		ServerName:                          c.ServerName,
		ClientAuth:                          c.ClientAuth,
		ClientCAs:                           c.ClientCAs,
		InsecureSkipVerify:                  c.InsecureSkipVerify,
		CipherSuites:                        c.CipherSuites,
		PreferServerCipherSuites:            c.PreferServerCipherSuites,
		SessionTicketsDisabled:              c.SessionTicketsDisabled,
		SessionTicketKey:                    c.SessionTicketKey,
		ClientSessionCache:                  c.ClientSessionCache,
		UnwrapSession:                       c.UnwrapSession,
		WrapSession:                         c.WrapSession,
		MinVersion:                          c.MinVersion,
		MaxVersion:                          c.MaxVersion,
		CurvePreferences:                    c.CurvePreferences,
		DynamicRecordSizingDisabled:         c.DynamicRecordSizingDisabled,
		Renegotiation:                       c.Renegotiation,
		KeyLogWriter:                        c.KeyLogWriter,
		EncryptedClientHelloConfigList:      c.EncryptedClientHelloConfigList,
		EncryptedClientHelloRejectionVerify: c.EncryptedClientHelloRejectionVerify,
		EncryptedClientHelloKeys:            c.EncryptedClientHelloKeys,
		sessionTicketKeys:                   c.sessionTicketKeys,
		autoSessionTicketKeys:               c.autoSessionTicketKeys,
	}
}

var deprecatedSessionTicketKey = []byte("DEPRECATED")

func (c *Config) initLegacySessionTicketKeyRLocked() {
	if c.SessionTicketKey != [32]byte{} &&
		(bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) || len(c.sessionTicketKeys) > 0) {
		return
	}

	c.mutex.RUnlock()
	defer c.mutex.RLock()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.SessionTicketKey == [32]byte{} {
		if _, err := io.ReadFull(c.rand(), c.SessionTicketKey[:]); err != nil {
			panic(fmt.Sprintf("tls: unable to generate random session ticket key: %v", err))
		}
		copy(c.SessionTicketKey[:], deprecatedSessionTicketKey)
	} else if !bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) && len(c.sessionTicketKeys) == 0 {
		c.sessionTicketKeys = []ticketKey{c.ticketKeyFromBytes(c.SessionTicketKey)}
	}

}

func (c *Config) ticketKeys(configForClient *Config) []ticketKey {
	if configForClient != nil {
		configForClient.mutex.RLock()
		if configForClient.SessionTicketsDisabled {
			configForClient.mutex.RUnlock()
			return nil
		}
		configForClient.initLegacySessionTicketKeyRLocked()
		if len(configForClient.sessionTicketKeys) != 0 {
			ret := configForClient.sessionTicketKeys
			configForClient.mutex.RUnlock()
			return ret
		}
		configForClient.mutex.RUnlock()
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if c.SessionTicketsDisabled {
		return nil
	}
	c.initLegacySessionTicketKeyRLocked()
	if len(c.sessionTicketKeys) != 0 {
		return c.sessionTicketKeys
	}
	if len(c.autoSessionTicketKeys) > 0 && c.time().Sub(c.autoSessionTicketKeys[0].created) < ticketKeyRotation {
		return c.autoSessionTicketKeys
	}

	c.mutex.RUnlock()
	defer c.mutex.RLock()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if len(c.autoSessionTicketKeys) == 0 || c.time().Sub(c.autoSessionTicketKeys[0].created) >= ticketKeyRotation {
		var newKey [32]byte
		if _, err := io.ReadFull(c.rand(), newKey[:]); err != nil {
			panic(fmt.Sprintf("unable to generate random session ticket key: %v", err))
		}
		valid := make([]ticketKey, 0, len(c.autoSessionTicketKeys)+1)
		valid = append(valid, c.ticketKeyFromBytes(newKey))
		for _, k := range c.autoSessionTicketKeys {
			if c.time().Sub(k.created) < ticketKeyLifetime {
				valid = append(valid, k)
			}
		}
		c.autoSessionTicketKeys = valid
	}
	return c.autoSessionTicketKeys
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

var supportedVersions = []uint16{
	VersionTLS13,
	VersionTLS12,
	VersionTLS11,
	VersionTLS10,
}

const roleServer = false

func (c *Config) supportedVersions(isClient bool) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if fips140tls.Required() && !slices.Contains(allowedSupportedVersionsFIPS, v) {
			continue
		}
		if (c == nil || c.MinVersion == 0) && v < VersionTLS12 {
			continue
		}
		if isClient && c.EncryptedClientHelloConfigList != nil && v < VersionTLS13 {
			continue
		}
		if c != nil && c.MinVersion != 0 && v < c.MinVersion {
			continue
		}
		if c != nil && c.MaxVersion != 0 && v > c.MaxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

func supportedVersionsFromMax(maxVersion uint16) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if v > maxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

func (c *Config) mutualVersion(isClient bool, peerVersions []uint16) (uint16, bool) {
	supportedVersions := c.supportedVersions(isClient)
	for _, v := range supportedVersions {
		if slices.Contains(peerVersions, v) {
			return v, true
		}
	}
	return 0, false
}

const (
	keyLogLabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	keyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
)

func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error {
	if c.KeyLogWriter == nil {
		return nil
	}

	logLine := fmt.Appendf(nil, "%s %x %x\n", label, clientRandom, secret)

	writerMutex.Lock()
	_, err := c.KeyLogWriter.Write(logLine)
	writerMutex.Unlock()

	return err
}

var writerMutex sync.Mutex

type Certificate struct {
	Certificate                  [][]byte
	PrivateKey                   crypto.PrivateKey
	SupportedSignatureAlgorithms []SignatureScheme
	OCSPStaple                   []byte
	SignedCertificateTimestamps  [][]byte
	Leaf                         *x509.Certificate
}

type handshakeMessage interface {
	marshal() ([]byte, error)
	unmarshal([]byte) bool
}

type handshakeMessageWithOriginalBytes interface {
	handshakeMessage

	originalBytes() []byte
}

func unexpectedMessageError(wanted, got any) error {
	return fmt.Errorf("tls: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

func supportedSignatureAlgorithms(minVers uint16) []SignatureScheme {
	sigAlgs := defaultSupportedSignatureAlgorithms()
	if fips140tls.Required() {
		sigAlgs = slices.DeleteFunc(sigAlgs, func(s SignatureScheme) bool {
			return !slices.Contains(allowedSignatureAlgorithmsFIPS, s)
		})
	}
	if minVers > VersionTLS12 {
		sigAlgs = slices.DeleteFunc(sigAlgs, func(s SignatureScheme) bool {
			sigType, sigHash, _ := typeAndHashFromSignatureScheme(s)
			return sigType == signaturePKCS1v15 || sigHash == crypto.SHA1
		})
	}
	return sigAlgs
}

func supportedSignatureAlgorithmsCert() []SignatureScheme {
	sigAlgs := defaultSupportedSignatureAlgorithmsCert()
	if fips140tls.Required() {
		sigAlgs = slices.DeleteFunc(sigAlgs, func(s SignatureScheme) bool {
			return !slices.Contains(allowedSignatureAlgorithmsFIPS, s)
		})
	}
	return sigAlgs
}
