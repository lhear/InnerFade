package tls13

import (
	"crypto/hkdf"
	"encoding/binary"
	"hash"
)

func ExpandLabel[H hash.Hash](hash func() H, secret []byte, label string, context []byte, length int) []byte {
	if len("tls13 ")+len(label) > 255 || len(context) > 255 {
		panic("tls13: label or context too long")
	}
	hkdfLabel := make([]byte, 0, 2+1+len("tls13 ")+len(label)+1+len(context))
	hkdfLabel = binary.BigEndian.AppendUint16(hkdfLabel, uint16(length))
	hkdfLabel = append(hkdfLabel, byte(len("tls13 ")+len(label)))
	hkdfLabel = append(hkdfLabel, "tls13 "...)
	hkdfLabel = append(hkdfLabel, label...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)
	b, _ := hkdf.Expand(hash, secret, string(hkdfLabel), length)
	return b
}

func extract[H hash.Hash](hash func() H, newSecret, currentSecret []byte) []byte {
	if newSecret == nil {
		newSecret = make([]byte, hash().Size())
	}
	b, _ := hkdf.Extract(hash, newSecret, currentSecret)
	return b
}

func deriveSecret[H hash.Hash](hash func() H, secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = hash()
	}
	return ExpandLabel(hash, secret, label, transcript.Sum(nil), transcript.Size())
}

const (
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	exporterLabel                 = "exp master"
	resumptionLabel               = "res master"
)

type EarlySecret struct {
	secret []byte
	hash   func() hash.Hash
}

func NewEarlySecret[H hash.Hash](h func() H, psk []byte) *EarlySecret {
	return &EarlySecret{
		secret: extract(h, psk, nil),
		hash:   func() hash.Hash { return h() },
	}
}

type HandshakeSecret struct {
	secret []byte
	hash   func() hash.Hash
}

func (s *EarlySecret) HandshakeSecret(sharedSecret []byte) *HandshakeSecret {
	derived := deriveSecret(s.hash, s.secret, "derived", nil)
	return &HandshakeSecret{
		secret: extract(s.hash, sharedSecret, derived),
		hash:   s.hash,
	}
}

func (s *HandshakeSecret) ClientHandshakeTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, clientHandshakeTrafficLabel, transcript)
}

func (s *HandshakeSecret) ServerHandshakeTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, serverHandshakeTrafficLabel, transcript)
}

type MasterSecret struct {
	secret []byte
	hash   func() hash.Hash
}

func (s *HandshakeSecret) MasterSecret() *MasterSecret {
	derived := deriveSecret(s.hash, s.secret, "derived", nil)
	return &MasterSecret{
		secret: extract(s.hash, nil, derived),
		hash:   s.hash,
	}
}

func (s *MasterSecret) ClientApplicationTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, clientApplicationTrafficLabel, transcript)
}

func (s *MasterSecret) ServerApplicationTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, serverApplicationTrafficLabel, transcript)
}

func (s *MasterSecret) ResumptionMasterSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, resumptionLabel, transcript)
}

type ExporterMasterSecret struct {
	secret []byte
	hash   func() hash.Hash
}

func (s *MasterSecret) ExporterMasterSecret(transcript hash.Hash) *ExporterMasterSecret {
	return &ExporterMasterSecret{
		secret: deriveSecret(s.hash, s.secret, exporterLabel, transcript),
		hash:   s.hash,
	}
}

func (s *ExporterMasterSecret) Exporter(label string, context []byte, length int) []byte {
	secret := deriveSecret(s.hash, s.secret, label, nil)
	h := s.hash()
	h.Write(context)
	return ExpandLabel(s.hash, secret, "exporter", h.Sum(nil), length)
}
