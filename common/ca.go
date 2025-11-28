package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"innerfade/logger"
)

type CA struct {
	CACert  *x509.Certificate
	CAKey   crypto.PrivateKey
	CertPEM []byte
	KeyPEM  []byte

	leafKey *ecdsa.PrivateKey

	certCache sync.Map
}

func NewCA(caCertPath, caKeyPath string) (*CA, error) {
	logger.Debugf("initializing CA: caCertPath=%s, caKeyPath=%s", caCertPath, caKeyPath)

	var ca *CA
	var err error

	if caCertPath != "" && caKeyPath != "" {
		logger.Info("loading CA certificate")
		ca, err = loadCA(caCertPath, caKeyPath)
	} else {
		logger.Info("certificate path not specified, generating temporary CA certificate")
		ca, err = GenerateTempCA()
	}

	if err != nil {
		return nil, err
	}

	logger.Debug("generating common leaf certificate ECC private key...")
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate common ECC private key: %w", err)
	}
	ca.leafKey = leafKey
	logger.Debug("common leaf certificate private key ready")

	return ca, nil
}

func loadCA(caCertPath, caKeyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate file: %w", err)
	}

	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key file: %w", err)
	}

	caCertBlock, _ := pem.Decode(certPEM)
	if caCertBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caKeyBlock, _ := pem.Decode(keyPEM)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	var caKey crypto.PrivateKey

	if caKey, err = x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes); err != nil {

		if caKey, err = x509.ParseECPrivateKey(caKeyBlock.Bytes); err != nil {

			if rsaKey, errRSA := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes); errRSA == nil {
				caKey = rsaKey
			} else {
				return nil, fmt.Errorf("failed to parse CA private key (supports PKCS8, EC, RSA): %w", err)
			}
		}
	}

	return &CA{
		CACert:  caCert,
		CAKey:   caKey,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

func GenerateTempCA() (*CA, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, err
	}

	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubKeyHash := sha256.Sum256(pubKeyBytes)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"InnerFade MITM Proxy"},
			CommonName:   "InnerFade MITM CA (ECC)",
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		SubjectKeyId:          pubKeyHash[:],
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return &CA{
		CACert:  caCert,
		CAKey:   priv,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

func (ca *CA) GenerateCert(hostname string) (*tls.Certificate, error) {
	logger.Debugf("generating new certificate (ECC): %s", hostname)

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, err
	}

	hosts := []string{hostname}
	if strings.HasPrefix(hostname, "*.") {
		hosts = append(hosts, strings.TrimPrefix(hostname, "*."))
	}

	leafKey := ca.leafKey

	leafPubBytes, _ := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)
	subjectKeyId := sha256.Sum256(leafPubBytes)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"InnerFade MITM Proxy"},
			CommonName:   hostname,
		},
		NotBefore:    time.Now().Add(-10 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     hosts,
		SubjectKeyId: subjectKeyId[:],
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.CACert, &leafKey.PublicKey, ca.CAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  leafKey,
		Leaf:        &template,
	}

	ca.certCache.Store(hostname, tlsCert)

	return tlsCert, nil
}

func (ca *CA) SaveToFile(certPath, keyPath string) error {
	if err := os.WriteFile(certPath, ca.CertPEM, 0644); err != nil {
		return fmt.Errorf("failed to save CA certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, ca.KeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save CA private key: %w", err)
	}
	logger.Infof("CA certificate saved: %s, %s", certPath, keyPath)
	return nil
}

func randomSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}
