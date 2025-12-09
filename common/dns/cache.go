package dns

import (
	"net"
	"sync"
	"time"
)

type resolverCache struct {
	store sync.Map
	stop  chan struct{}
	once  sync.Once
}

func newCache() *resolverCache {
	c := &resolverCache{
		stop: make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

func (c *resolverCache) get(key cacheKey) ([]net.IP, bool) {
	val, ok := c.store.Load(key)
	if !ok {
		return nil, false
	}
	entry := val.(cacheEntry)
	if time.Now().UnixNano() > entry.expiresAt {
		c.store.Delete(key)
		return nil, false
	}
	out := make([]net.IP, len(entry.ips))
	copy(out, entry.ips)
	return out, true
}

func (c *resolverCache) set(key cacheKey, ips []net.IP) {
	storedIPs := make([]net.IP, len(ips))
	copy(storedIPs, ips)

	c.store.Store(key, cacheEntry{
		ips:       storedIPs,
		expiresAt: time.Now().Add(cacheTTL).UnixNano(),
	})
}

func (c *resolverCache) cleanupLoop() {
	ticker := time.NewTicker(cleanupIntv)
	defer ticker.Stop()

	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			c.store.Range(func(key, value interface{}) bool {
				entry := value.(cacheEntry)
				if now > entry.expiresAt {
					c.store.Delete(key)
				}
				return true
			})
		}
	}
}

func (c *resolverCache) close() {
	c.once.Do(func() {
		close(c.stop)
	})
}