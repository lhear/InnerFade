package server

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"innerfade/common/cache"
	"innerfade/common/reality"
	"innerfade/config"
	"innerfade/logger"
)

const (
	HandshakeTimeout = 5 * time.Second
	DialTimeout      = 10 * time.Second
	KeepAlive        = 30 * time.Second
)

var domainCache *cache.DomainCache

type Server struct {
	config         *config.Config
	dialer         *net.Dialer
	proxyDialer    proxy.Dialer
	handshakeCache sync.Map
	encryptionKey  []byte
	privateKey     []byte
}

func Start(cfg *config.Config) error {
	var err error
	domainCache, err = cache.NewDomainCache(cfg.CachePath)
	if err != nil {
		return err
	}

	server := &Server{
		config: cfg,
		dialer: &net.Dialer{
			Timeout:   DialTimeout,
			KeepAlive: KeepAlive,
		},
	}

	if cfg.Socks5Proxy != "" {
		logger.Infof("configuring SOCKS5 proxy: %s", cfg.Socks5Proxy)
		server.proxyDialer, err = proxy.SOCKS5("tcp", cfg.Socks5Proxy, nil, proxy.Direct)
		if err != nil {
			return fmt.Errorf("failed to initialize SOCKS5 proxy: %w", err)
		}
	} else {

		server.proxyDialer = proxy.Direct
	}

	server.privateKey, _ = base64.RawURLEncoding.DecodeString(cfg.PrivateKey)

	p, _ := ecdh.X25519().NewPrivateKey(server.privateKey)
	server.encryptionKey, err = hkdf.Extract(sha256.New, p.PublicKey().Bytes(), []byte("InnerFade"))
	if err != nil {
		return err
	}

	serverConfig := &reality.Config{
		PrivateKey:  server.privateKey,
		ServerNames: cfg.ServerNames,
		ShortIds:    [][]byte{{0, 0, 0, 0, 0, 0, 0, 0}},
		Show:        logger.IsDebugEnabled(),
		Dest:        cfg.Dest,
		Type:        "tcp",
	}

	serverConfig.GetServerRandomForClient = server.handleClientRandom

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on server address %s: %w", cfg.ListenAddr, err)
	}
	logger.Infof("listening on %s", cfg.ListenAddr)
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Errorf("failed to accept connection: %v", err)
			continue
		}
		go func(conn net.Conn) {
			remoteAddr := conn.RemoteAddr().String()
			logger.Infof("[%s] accepted connection", remoteAddr)

			conn, err := reality.Server(conn, serverConfig)
			if err != nil {
				server.handshakeCache.LoadAndDelete(remoteAddr)
				logger.Errorf("[%s] failed to accept connection: %v", remoteAddr, err)
				return
			}
			server.acceptConnection(conn)
		}(conn)
	}
}
