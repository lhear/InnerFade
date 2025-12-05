package reality

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"slices"
	"time"

	"innerfade/common/reality/server/tls13"
)

type serverHandshakeStateTLS13 struct {
	c               *Conn
	ctx             context.Context
	clientHello     *clientHelloMsg
	hello           *serverHelloMsg
	sentDummyCCS    bool
	usingPSK        bool
	suite           *cipherSuiteTLS13
	cert            *Certificate
	sigAlg          SignatureScheme
	earlySecret     *tls13.EarlySecret
	sharedKey       []byte
	handshakeSecret *tls13.HandshakeSecret
	masterSecret    *tls13.MasterSecret
	trafficSecret   []byte
	transcript      hash.Hash
	clientFinished  []byte
}

var (
	ed25519Priv ed25519.PrivateKey
	signedCert  []byte
)

func init() {
	certificate := x509.Certificate{SerialNumber: &big.Int{}}
	_, ed25519Priv, _ = ed25519.GenerateKey(rand.Reader)
	signedCert, _ = x509.CreateCertificate(rand.Reader, &certificate, &certificate, ed25519.PublicKey(ed25519Priv[32:]), ed25519Priv)
}

func (hs *serverHandshakeStateTLS13) handshake() error {
	c := hs.c
	if c.config.Show {
		remoteAddr := c.RemoteAddr().String()
		fmt.Printf("REALITY remoteAddr: %v\tis using X25519MLKEM768 for TLS' communication: %v\n", remoteAddr, hs.hello.serverShare.group == X25519MLKEM768)
	}

	{
		hs.suite = cipherSuiteTLS13ByID(hs.hello.cipherSuite)
		c.cipherSuite = hs.suite.id
		hs.transcript = hs.suite.hash.New()

		var peerData []byte
		for _, keyShare := range hs.clientHello.keyShares {
			if keyShare.group == hs.hello.serverShare.group {
				peerData = keyShare.data
				break
			}
		}

		var peerPub = peerData
		if hs.hello.serverShare.group == X25519MLKEM768 {
			peerPub = peerData[mlkem.EncapsulationKeySize768:]
		}

		key, _ := generateECDHEKey(c.config.rand(), X25519)
		copy(hs.hello.serverShare.data, key.PublicKey().Bytes())
		peerKey, _ := key.Curve().NewPublicKey(peerPub)
		hs.sharedKey, _ = key.ECDH(peerKey)

		if hs.hello.serverShare.group == X25519MLKEM768 {
			k, _ := mlkem.NewEncapsulationKey768(peerData[:mlkem.EncapsulationKeySize768])
			mlkemSharedSecret, ciphertext := k.Encapsulate()
			hs.sharedKey = append(mlkemSharedSecret, hs.sharedKey...)
			copy(hs.hello.serverShare.data, append(ciphertext, hs.hello.serverShare.data[:32]...))
		}

		c.serverName = hs.clientHello.serverName
	}
	{
		var cert []byte
		cert = bytes.Clone(signedCert)

		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(ed25519Priv[32:])
		h.Sum(cert[:len(cert)-64])

		hs.cert = &Certificate{
			Certificate: [][]byte{cert},
			PrivateKey:  ed25519Priv,
		}
		hs.sigAlg = Ed25519
	}
	c.buffering = true
	if err := hs.sendServerParameters(); err != nil {
		return err
	}
	if err := hs.sendServerCertificate(); err != nil {
		return err
	}
	if err := hs.sendServerFinished(); err != nil {
		return err
	}
	if hs.c.out.handshakeLen[6] != 0 {
		if _, err := c.writeRecord(recordTypeHandshake, []byte{typeNewSessionTicket}); err != nil {
			return err
		}
	}
	if _, err := c.flush(); err != nil {
		return err
	}
	return nil
}

func (hs *serverHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	return hs.c.writeChangeCipherRecord()
}

func (hs *serverHandshakeStateTLS13) sendServerParameters() error {
	c := hs.c

	if err := transcriptMsg(hs.clientHello, hs.transcript); err != nil {
		return err
	}

	{
		hs.transcript.Write(hs.hello.original)
		if _, err := hs.c.writeRecord(recordTypeHandshake, hs.hello.original); err != nil {
			return err
		}
	}

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}

	earlySecret := hs.earlySecret
	if earlySecret == nil {
		earlySecret = tls13.NewEarlySecret(hs.suite.hash.New, nil)
	}
	hs.handshakeSecret = earlySecret.HandshakeSecret(hs.sharedKey)

	clientSecret := hs.handshakeSecret.ClientHandshakeTrafficSecret(hs.transcript)
	c.in.setTrafficSecret(hs.suite, clientSecret)
	serverSecret := hs.handshakeSecret.ServerHandshakeTrafficSecret(hs.transcript)
	c.out.setTrafficSecret(hs.suite, serverSecret)

	err := c.config.writeKeyLog(keyLogLabelClientHandshake, hs.clientHello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	encryptedExtensions := new(encryptedExtensionsMsg)
	encryptedExtensions.alpnProtocol = c.clientProtocol

	if _, err := hs.c.writeHandshakeRecord(encryptedExtensions, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) requestClientCert() bool {
	return hs.c.config.ClientAuth >= RequestClientCert && !hs.usingPSK
}

func (hs *serverHandshakeStateTLS13) sendServerCertificate() error {
	c := hs.c

	if hs.usingPSK {
		return nil
	}

	if hs.requestClientCert() {
		certReq := new(certificateRequestMsgTLS13)
		certReq.ocspStapling = true
		certReq.scts = true
		certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms(c.vers)
		certReq.supportedSignatureAlgorithmsCert = supportedSignatureAlgorithmsCert()
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}

		if _, err := hs.c.writeHandshakeRecord(certReq, hs.transcript); err != nil {
			return err
		}
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *hs.cert
	certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0

	if _, err := hs.c.writeHandshakeRecord(certMsg, hs.transcript); err != nil {
		return err
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true
	certVerifyMsg.signatureAlgorithm = hs.sigAlg

	sigType, sigHash, err := typeAndHashFromSignatureScheme(hs.sigAlg)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := hs.cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		public := hs.cert.PrivateKey.(crypto.Signer).Public()
		if rsaKey, ok := public.(*rsa.PublicKey); ok && sigType == signatureRSAPSS &&
			rsaKey.N.BitLen()/8 < sigHash.Size()*2+2 {
			c.sendAlert(alertHandshakeFailure)
		} else {
			c.sendAlert(alertInternalError)
		}
		return errors.New("tls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig

	if _, err := hs.c.writeHandshakeRecord(certVerifyMsg, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) sendServerFinished() error {
	c := hs.c

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}

	if _, err := hs.c.writeHandshakeRecord(finished, hs.transcript); err != nil {
		return err
	}

	hs.masterSecret = hs.handshakeSecret.MasterSecret()

	hs.trafficSecret = hs.masterSecret.ClientApplicationTrafficSecret(hs.transcript)
	serverSecret := hs.masterSecret.ServerApplicationTrafficSecret(hs.transcript)
	c.out.setTrafficSecret(hs.suite, serverSecret)

	err := c.config.writeKeyLog(keyLogLabelClientTraffic, hs.clientHello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	if !hs.requestClientCert() {
		if err := hs.sendSessionTickets(); err != nil {
			return err
		}
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) shouldSendSessionTickets() bool {
	if hs.c.config.SessionTicketsDisabled {
		return false
	}

	return slices.Contains(hs.clientHello.pskModes, pskModeDHE)
}

func (hs *serverHandshakeStateTLS13) sendSessionTickets() error {
	c := hs.c

	hs.clientFinished = hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	finishedMsg := &finishedMsg{
		verifyData: hs.clientFinished,
	}
	if err := transcriptMsg(finishedMsg, hs.transcript); err != nil {
		return err
	}

	c.resumptionSecret = hs.masterSecret.ResumptionMasterSecret(hs.transcript)

	if !hs.shouldSendSessionTickets() {
		return nil
	}
	return c.sendSessionTicket(false, nil)
}

func (c *Conn) sendSessionTicket(earlyData bool, extra [][]byte) error {
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	if suite == nil {
		return errors.New("tls: internal error: unknown cipher suite")
	}
	psk := tls13.ExpandLabel(suite.hash.New, c.resumptionSecret, "resumption",
		nil, suite.hash.Size())

	m := new(newSessionTicketMsgTLS13)

	state := c.sessionState()
	state.secret = psk
	state.EarlyData = earlyData
	state.Extra = extra
	if c.config.WrapSession != nil {
		var err error
		m.label, err = c.config.WrapSession(c.connectionStateLocked(), state)
		if err != nil {
			return err
		}
	} else {
		stateBytes, err := state.Bytes()
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		m.label, err = c.config.encryptTicket(stateBytes, c.ticketKeys)
		if err != nil {
			return err
		}
	}
	m.lifetime = uint32(maxSessionTicketLifetime / time.Second)

	ageAdd := make([]byte, 4)
	if _, err := c.config.rand().Read(ageAdd); err != nil {
		return err
	}
	m.ageAdd = binary.LittleEndian.Uint32(ageAdd)

	if earlyData {
		m.maxEarlyData = 0xffffffff
	}

	if _, err := c.writeHandshakeRecord(m, nil); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) readClientFinished() error {
	c := hs.c

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}

	if !hmac.Equal(hs.clientFinished, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid client finished hash")
	}

	c.in.setTrafficSecret(hs.suite, hs.trafficSecret)

	return nil
}
