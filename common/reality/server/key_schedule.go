package reality

import (
	"crypto/ecdh"
	"crypto/hmac"
	"errors"
	"hash"
	"io"

	"innerfade/common/reality/server/tls13"
)

func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
	return tls13.ExpandLabel(c.hash.New, trafficSecret, "traffic upd", nil, c.hash.Size())
}

func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte) {
	key = tls13.ExpandLabel(c.hash.New, trafficSecret, "key", nil, c.keyLen)
	iv = tls13.ExpandLabel(c.hash.New, trafficSecret, "iv", nil, aeadNonceLength)
	return
}

func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) []byte {
	finishedKey := tls13.ExpandLabel(c.hash.New, baseKey, "finished", nil, c.hash.Size())
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil)
}

func (c *cipherSuiteTLS13) exportKeyingMaterial(s *tls13.MasterSecret, transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
	expMasterSecret := s.ExporterMasterSecret(transcript)
	return func(label string, context []byte, length int) ([]byte, error) {
		return expMasterSecret.Exporter(label, context, length), nil
	}
}

func generateECDHEKey(rand io.Reader, curveID CurveID) (*ecdh.PrivateKey, error) {
	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported curve")
	}

	return curve.GenerateKey(rand)
}

func curveForCurveID(id CurveID) (ecdh.Curve, bool) {
	switch id {
	case X25519:
		return ecdh.X25519(), true
	case CurveP256:
		return ecdh.P256(), true
	case CurveP384:
		return ecdh.P384(), true
	case CurveP521:
		return ecdh.P521(), true
	default:
		return nil, false
	}
}
