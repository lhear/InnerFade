package reality

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type SessionState struct {
	Extra            [][]byte
	EarlyData        bool
	version          uint16
	isClient         bool
	cipherSuite      uint16
	createdAt        uint64
	secret           []byte
	extMasterSecret  bool
	peerCertificates []*x509.Certificate
	ocspResponse     []byte
	scts             [][]byte
	verifiedChains   [][]*x509.Certificate
	alpnProtocol     string
	useBy            uint64
	ageAdd           uint32
	ticket           []byte
	curveID          CurveID
}

func (s *SessionState) Bytes() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(s.version)
	if s.isClient {
		b.AddUint8(2)
	} else {
		b.AddUint8(1)
	}
	b.AddUint16(s.cipherSuite)
	addUint64(&b, s.createdAt)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(s.secret)
	})
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, extra := range s.Extra {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extra)
			})
		}
	})
	if s.extMasterSecret {
		b.AddUint8(1)
	} else {
		b.AddUint8(0)
	}
	if s.EarlyData {
		b.AddUint8(1)
	} else {
		b.AddUint8(0)
	}
	marshalCertificate(&b, Certificate{
		Certificate:                 certificatesToBytesSlice(s.peerCertificates),
		OCSPStaple:                  s.ocspResponse,
		SignedCertificateTimestamps: s.scts,
	})
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, chain := range s.verifiedChains {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				if len(chain) == 0 {
					b.SetError(errors.New("tls: internal error: empty verified chain"))
					return
				}
				for _, cert := range chain[1:] {
					b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(cert.Raw)
					})
				}
			})
		}
	})
	if s.EarlyData {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(s.alpnProtocol))
		})
	}
	if s.version >= VersionTLS13 {
		if s.isClient {
			addUint64(&b, s.useBy)
			b.AddUint32(s.ageAdd)
		}
	} else {
		b.AddUint16(uint16(s.curveID))
	}
	return b.Bytes()
}

func certificatesToBytesSlice(certs []*x509.Certificate) [][]byte {
	s := make([][]byte, 0, len(certs))
	for _, c := range certs {
		s = append(s, c.Raw)
	}
	return s
}

func (c *Conn) sessionState() *SessionState {
	return &SessionState{
		version:          c.vers,
		cipherSuite:      c.cipherSuite,
		createdAt:        uint64(c.config.time().Unix()),
		alpnProtocol:     c.clientProtocol,
		peerCertificates: c.peerCertificates,
		ocspResponse:     c.ocspResponse,
		scts:             c.scts,
		isClient:         c.isClient,
		extMasterSecret:  c.extMasterSecret,
		verifiedChains:   c.verifiedChains,
		curveID:          c.curveID,
	}
}

func (c *Config) EncryptTicket(cs ConnectionState, ss *SessionState) ([]byte, error) {
	ticketKeys := c.ticketKeys(nil)
	stateBytes, err := ss.Bytes()
	if err != nil {
		return nil, err
	}
	return c.encryptTicket(stateBytes, ticketKeys)
}

func (c *Config) encryptTicket(state []byte, ticketKeys []ticketKey) ([]byte, error) {
	if len(ticketKeys) == 0 {
		return nil, errors.New("tls: internal error: session ticket keys unavailable")
	}

	encrypted := make([]byte, aes.BlockSize+len(state)+sha256.Size)
	iv := encrypted[:aes.BlockSize]
	ciphertext := encrypted[aes.BlockSize : len(encrypted)-sha256.Size]
	authenticated := encrypted[:len(encrypted)-sha256.Size]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	if _, err := io.ReadFull(c.rand(), iv); err != nil {
		return nil, err
	}
	key := ticketKeys[0]
	block, err := aes.NewCipher(key.aesKey[:])
	if err != nil {
		return nil, errors.New("tls: failed to create cipher while encrypting ticket: " + err.Error())
	}
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, state)

	mac := hmac.New(sha256.New, key.hmacKey[:])
	mac.Write(authenticated)
	mac.Sum(macBytes[:0])

	return encrypted, nil
}

type ClientSessionState struct {
	session *SessionState
}

func (cs *ClientSessionState) ResumptionState() (ticket []byte, state *SessionState, err error) {
	if cs == nil || cs.session == nil {
		return nil, nil, nil
	}
	return cs.session.ticket, cs.session, nil
}

func NewResumptionState(ticket []byte, state *SessionState) (*ClientSessionState, error) {
	state.ticket = ticket
	return &ClientSessionState{
		session: state,
	}, nil
}
