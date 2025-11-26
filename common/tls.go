package common

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync"

	"innerfade/logger"
)

type TLSConfigCache struct {
	mu    sync.RWMutex
	cache map[string]*tls.Config
}

func NewTLSConfigCache() *TLSConfigCache {
	return &TLSConfigCache{
		cache: make(map[string]*tls.Config),
	}
}

func (c *TLSConfigCache) GetConfig(host string, cert *tls.Certificate) *tls.Config {
	c.mu.RLock()
	if config, exists := c.cache[host]; exists {
		c.mu.RUnlock()
		return config
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if config, exists := c.cache[host]; exists {
		return config
	}

	logger.Debugf("creating new TLS configuration: %s", host)
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	}

	c.cache[host] = config
	return config
}

func ParseHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		logger.Errorf("failed to parse address %s: %v", addr, err)
		return "", 0, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		var pErr error
		port, pErr = net.LookupPort("tcp", portStr)
		if pErr != nil {
			logger.Errorf("failed to look up port %s: %v", portStr, pErr)
			return "", 0, pErr
		}
	}

	return host, port, nil
}
