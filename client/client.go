package client

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"innerfade/common"
	"innerfade/common/cache"
	"innerfade/config"
	"innerfade/logger"
)

var domainCache *cache.DomainCache

type Client struct {
	config        *config.Config
	ca            *common.CA
	tlsCache      *common.TLSConfigCache
	certCache     *CertCache
	serverAddr    string
	encryptionKey []byte
	publicKey     []byte
	dialer        *net.Dialer
}

type cachedCert struct {
	cert      *tls.Certificate
	generated time.Time
}

type CertCache struct {
	cache sync.Map
}

func NewCertCache() *CertCache {
	c := &CertCache{}
	go c.cleanup()
	return c
}

func (cc *CertCache) Get(hostname string, ca *common.CA) (*tls.Certificate, bool) {
	if val, ok := cc.cache.Load(hostname); ok {
		item := val.(*cachedCert)
		if time.Since(item.generated) < 60*time.Minute {
			return item.cert, true
		}
		cc.cache.Delete(hostname)
	}

	newCert, err := ca.GenerateCert(hostname)
	if err != nil {
		logger.Errorf("failed to generate certificate [%s]: %v", hostname, err)
		return nil, false
	}

	cc.cache.Store(hostname, &cachedCert{
		cert:      newCert,
		generated: time.Now(),
	})

	return newCert, false
}

func (cc *CertCache) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		cc.cache.Range(func(key, value interface{}) bool {
			item := value.(*cachedCert)
			if now.Sub(item.generated) >= 70*time.Minute {
				cc.cache.Delete(key)
			}
			return true
		})
	}
}

func Start(cfg *config.Config) error {
	var err error
	domainCache, err = cache.NewDomainCache(cfg.CachePath)
	if err != nil {
		return err
	}

	caInstance, err := common.NewCA(cfg.CACert, cfg.CAKey)
	if err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	client := &Client{
		config:     cfg,
		ca:         caInstance,
		tlsCache:   common.NewTLSConfigCache(),
		certCache:  NewCertCache(),
		serverAddr: cfg.ServerAddr,
		dialer: &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}

	client.publicKey, _ = base64.RawURLEncoding.DecodeString(cfg.PublicKey)

	client.encryptionKey, err = hkdf.Extract(sha256.New, client.publicKey, []byte("InnerFade"))
	if err != nil {
		return err
	}

	proxy := &http.Server{
		Addr:        cfg.ListenAddr,
		Handler:     http.HandlerFunc(client.handleProxy),
		IdleTimeout: 60 * time.Second,
	}

	logger.Infof("listening on %s", cfg.ListenAddr)
	return proxy.ListenAndServe()
}
