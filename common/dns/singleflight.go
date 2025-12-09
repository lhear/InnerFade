package dns

import (
	"net"
	"sync"
)

type singleflightGroup struct {
	mu sync.Mutex
	m  map[cacheKey]*call
}

type call struct {
	wg  sync.WaitGroup
	val []net.IP
	err error
}

func (g *singleflightGroup) Do(key cacheKey, fn func() ([]net.IP, error)) ([]net.IP, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[cacheKey]*call)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		if c.val == nil {
			return nil, c.err
		}
		out := make([]net.IP, len(c.val))
		copy(out, c.val)
		return out, c.err
	}
	c := new(call)
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return c.val, c.err
}