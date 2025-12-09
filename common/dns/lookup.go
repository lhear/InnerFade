package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dnsPort        = "53"
	maxBufferSize  = 4096
	maxCNAMEDepth  = 5
	defaultTimeout = 5 * time.Second
	maxRetries     = 2
	cacheTTL       = 300 * time.Second
	cleanupIntv    = 60 * time.Second
)

const (
	dnsTypeA     = 1
	dnsTypeCNAME = 5
	dnsTypeAAAA  = 28
	dnsTypeOPT   = 41
	dnsClassIN   = 1
	ednsCodeECS  = 8
)

var (
	ErrMaxRecursion = errors.New("maximum CNAME recursion depth reached")
	ErrInvalidResp  = errors.New("invalid DNS response")
	ErrNoIPFound    = errors.New("no IP addresses found")
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, maxBufferSize)
		return &b
	},
}

var globalID uint32

func init() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	globalID = r.Uint32()
}

func generateID() uint16 {
	return uint16(atomic.AddUint32(&globalID, 1))
}

type cacheKey struct {
	host     string
	clientIP string
	qType    uint16
}

type cacheEntry struct {
	ips       []net.IP
	expiresAt int64
}

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

type ECSResolver struct {
	Upstream   string
	Timeout    time.Duration
	MaxRetries int
	clientIP   net.IP
	preferIPv6 bool
	cache      *resolverCache
	sf         singleflightGroup
}

func NewECSResolver(conf string) (*ECSResolver, error) {
	if conf == "" {
		return nil, errors.New("configuration cannot be empty")
	}
	var (
		upstream   string
		clientIP   net.IP
		preferIPv6 bool
	)
	if idx := strings.LastIndex(conf, "#"); idx != -1 {
		boolStr := conf[idx+1:]
		if boolStr == "" {
			return nil, errors.New("empty preferIPv6 value after '#'")
		}
		val, err := strconv.ParseBool(boolStr)
		if err != nil {
			return nil, fmt.Errorf("invalid boolean value for preferIPv6: %q", boolStr)
		}
		preferIPv6 = val
		conf = conf[:idx]
	}
	if idx := strings.LastIndex(conf, "@"); idx != -1 {
		ipStr := conf[idx+1:]
		if ipStr == "" {
			return nil, errors.New("empty ECS client IP after '@'")
		}
		clientIP = net.ParseIP(ipStr)
		if clientIP == nil {
			return nil, fmt.Errorf("invalid ECS client IP: %q", ipStr)
		}
		upstream = conf[:idx]
	} else {
		upstream = conf
	}
	if upstream == "" {
		return nil, errors.New("upstream address cannot be empty")
	}
	host, port, err := net.SplitHostPort(upstream)
	if err != nil {
		host = strings.Trim(strings.Trim(upstream, "["), "]")
		port = dnsPort
	}
	if host == "" {
		return nil, errors.New("upstream host cannot be empty")
	}
	normalizedUpstream := net.JoinHostPort(host, port)
	if _, err := net.ResolveUDPAddr("udp", normalizedUpstream); err != nil {
		return nil, fmt.Errorf("invalid upstream address %q: %w", normalizedUpstream, err)
	}
	return &ECSResolver{
		Upstream:   normalizedUpstream,
		Timeout:    defaultTimeout,
		MaxRetries: maxRetries,
		clientIP:   clientIP,
		cache:      newCache(),
		preferIPv6: preferIPv6,
	}, nil
}

func (r *ECSResolver) Close() {
	if r.cache != nil {
		r.cache.close()
	}
}

func (r *ECSResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if host == "" {
		return nil, errors.New("empty host")
	}
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	ips, err := r.lookupDualStack(ctx, host)
	if err != nil {
		return nil, err
	}
	reorderIPs(ips, r.preferIPv6)
	return ips, nil
}

func reorderIPs(ips []net.IP, preferIPv6 bool) {
	if len(ips) <= 1 {
		return
	}
	var v4s []net.IP
	var v6s []net.IP

	for _, ip := range ips {
		if ip.To4() != nil {
			v4s = append(v4s, ip)
		} else {
			v6s = append(v6s, ip)
		}
	}
	var primary, secondary []net.IP
	if preferIPv6 {
		primary = v6s
		secondary = v4s
	} else {
		primary = v4s
		secondary = v6s
	}

	i := 0
	pLen, sLen := len(primary), len(secondary)
	maxLen := max(sLen, pLen)

	for k := range maxLen {
		if k < pLen {
			ips[i] = primary[k]
			i++
		}
		if k < sLen {
			ips[i] = secondary[k]
			i++
		}
	}
}

func (r *ECSResolver) lookupDualStack(ctx context.Context, host string) ([]net.IP, error) {
	type result struct {
		ips []net.IP
		err error
	}

	resCh := make(chan result, 2)
	var wg sync.WaitGroup

	doQuery := func(qType uint16) {
		defer wg.Done()
		ips, err := r.resolveWithSingleflight(ctx, host, qType)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		if len(ips) > 0 {
			resCh <- result{ips: ips}
		}
	}

	wg.Add(2)
	go doQuery(dnsTypeA)
	go doQuery(dnsTypeAAAA)

	go func() {
		wg.Wait()
		close(resCh)
	}()

	var allIPs []net.IP
	allIPs = make([]net.IP, 0, 4)

	var lastErr error
	successCount := 0

	for res := range resCh {
		if res.err != nil {
			lastErr = res.err
			continue
		}
		if len(res.ips) > 0 {
			allIPs = append(allIPs, res.ips...)
			successCount++
		}
	}

	if successCount == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, ErrNoIPFound
	}

	return allIPs, nil
}

func (r *ECSResolver) resolveWithSingleflight(ctx context.Context, host string, qType uint16) ([]net.IP, error) {
	key := cacheKey{
		host:     host,
		qType:    qType,
		clientIP: string(r.clientIP),
	}

	if ips, hit := r.cache.get(key); hit {
		return ips, nil
	}

	return r.sf.Do(key, func() ([]net.IP, error) {
		if ips, hit := r.cache.get(key); hit {
			return ips, nil
		}

		ips, err := r.resolveRecursively(ctx, host, qType, 0)
		if err == nil && len(ips) > 0 {
			r.cache.set(key, ips)
		}
		return ips, err
	})
}

func (r *ECSResolver) resolveRecursively(ctx context.Context, host string, qType uint16, depth int) ([]net.IP, error) {
	if depth > maxCNAMEDepth {
		return nil, ErrMaxRecursion
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	resp, err := r.exchangeWithRetry(ctx, host, qType)
	if err != nil {
		return nil, err
	}

	if len(resp.IPs) > 0 {
		return resp.IPs, nil
	}

	if resp.CNAME != "" {
		return r.resolveRecursively(ctx, resp.CNAME, qType, depth+1)
	}

	return nil, nil
}

func (r *ECSResolver) exchangeWithRetry(ctx context.Context, host string, qType uint16) (*dnsResponse, error) {
	var lastErr error
	var timer *time.Timer

	for i := 0; i <= r.MaxRetries; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if i > 0 {
			delay := 100 * time.Millisecond * time.Duration(1<<(i-1))
			if timer == nil {
				timer = time.NewTimer(delay)
			} else {
				timer.Reset(delay)
			}

			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}

		res, err := r.exchange(ctx, host, qType)
		if err == nil {
			if timer != nil {
				timer.Stop()
			}
			return res, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("failed after %d retries: %w", r.MaxRetries, lastErr)
}

type dnsResponse struct {
	IPs   []net.IP
	CNAME string
}

func (r *ECSResolver) exchange(ctx context.Context, host string, qType uint16) (*dnsResponse, error) {
	id := generateID()

	reqBufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(reqBufPtr)

	*reqBufPtr = (*reqBufPtr)[:0]
	reqData := *reqBufPtr

	var err error
	reqData, err = buildRequestAppend(reqData, host, qType, id, r.clientIP)
	if err != nil {
		return nil, err
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", r.Upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if udpConn, ok := conn.(*net.UDPConn); ok {
		_ = udpConn.SetReadBuffer(65535)
		_ = udpConn.SetWriteBuffer(65535)
	}

	deadline := time.Now().Add(r.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(reqData); err != nil {
		return nil, err
	}

	respBufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(respBufPtr)
	if cap(*respBufPtr) < maxBufferSize {
		*respBufPtr = make([]byte, maxBufferSize)
	}
	respBuf := (*respBufPtr)[:maxBufferSize]

	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, err
	}

	return parseResponse(respBuf[:n], id)
}

func buildRequestAppend(buf []byte, host string, qType uint16, id uint16, ecsIP net.IP) ([]byte, error) {
	buf = binary.BigEndian.AppendUint16(buf, id)
	buf = binary.BigEndian.AppendUint16(buf, 0x0100)
	buf = binary.BigEndian.AppendUint16(buf, 1)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, 1)

	var err error
	buf, err = appendDomainName(buf, host)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint16(buf, qType)
	buf = binary.BigEndian.AppendUint16(buf, dnsClassIN)

	buf = append(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, dnsTypeOPT)
	buf = binary.BigEndian.AppendUint16(buf, 1232)
	buf = binary.BigEndian.AppendUint32(buf, 0)
	ecsPayload, err := buildECSData(ecsIP)
	if err != nil {
		return nil, err
	}

	rdLen := 4 + len(ecsPayload)
	buf = binary.BigEndian.AppendUint16(buf, uint16(rdLen))

	buf = binary.BigEndian.AppendUint16(buf, ednsCodeECS)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(ecsPayload)))
	buf = append(buf, ecsPayload...)

	return buf, nil
}

func buildECSData(ip net.IP) ([]byte, error) {
	if ip == nil {
		return []byte{0, 1, 0, 0}, nil
	}

	family := uint16(1)
	prefixLen := uint8(24)
	targetIP := ip.To4()
	if targetIP != nil {
		family = 1
	} else {
		targetIP = ip.To16()
		if targetIP == nil {
			return nil, errors.New("invalid ECS IP")
		}
		family = 2
		prefixLen = 56
	}

	numBytes := (int(prefixLen) + 7) / 8
	if numBytes > len(targetIP) {
		numBytes = len(targetIP)
	}

	buf := make([]byte, 4+numBytes)
	binary.BigEndian.PutUint16(buf[0:2], family)
	buf[2] = prefixLen
	buf[3] = 0
	copy(buf[4:], targetIP[:numBytes])

	return buf, nil
}

func appendDomainName(buf []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 {
		return nil, errors.New("domain name too long")
	}

	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			partLen := i - start
			if partLen == 0 {
				start = i + 1
				continue
			}
			if partLen > 63 {
				return nil, errors.New("domain label too long")
			}
			buf = append(buf, byte(partLen))
			buf = append(buf, name[start:i]...)
			start = i + 1
		}
	}
	if start < len(name) {
		partLen := len(name) - start
		if partLen > 63 {
			return nil, errors.New("domain label too long")
		}
		buf = append(buf, byte(partLen))
		buf = append(buf, name[start:]...)
	}
	buf = append(buf, 0)
	return buf, nil
}

type dnsParser struct {
	data []byte
	pos  int
}

func (p *dnsParser) readUint16() (uint16, error) {
	if p.pos+2 > len(p.data) {
		return 0, ErrInvalidResp
	}
	v := binary.BigEndian.Uint16(p.data[p.pos:])
	p.pos += 2
	return v, nil
}

func (p *dnsParser) skip(n int) error {
	if p.pos+n > len(p.data) {
		return ErrInvalidResp
	}
	p.pos += n
	return nil
}

func (p *dnsParser) readName() (string, error) {
	var (
		sb       strings.Builder
		jumped   = false
		ptrCount = 0
		currPos  = p.pos
		finalPos = -1
	)
	for {
		if currPos >= len(p.data) {
			return "", ErrInvalidResp
		}
		b := p.data[currPos]
		if b == 0 {
			currPos++
			if !jumped {
				p.pos = currPos
			} else {
				p.pos = finalPos
			}
			s := sb.String()
			if len(s) > 0 && s[len(s)-1] == '.' {
				return s[:len(s)-1], nil
			}
			return s, nil
		}
		if (b & 0xC0) == 0xC0 {
			ptrCount++
			if ptrCount > 10 {
				return "", errors.New("dns name loop detected")
			}
			if currPos+2 > len(p.data) {
				return "", ErrInvalidResp
			}
			offset := binary.BigEndian.Uint16(p.data[currPos:]) & 0x3FFF
			if !jumped {
				finalPos = currPos + 2
			}
			currPos = int(offset)
			jumped = true
			continue
		}
		labelLen := int(b)
		currPos++
		if currPos+labelLen > len(p.data) {
			return "", ErrInvalidResp
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(p.data[currPos : currPos+labelLen])
		currPos += labelLen
		if !jumped {
			p.pos = currPos
		}
		if sb.Len() > 255 {
			return "", errors.New("domain name too long")
		}
	}
}

func parseResponse(data []byte, reqID uint16) (*dnsResponse, error) {
	p := &dnsParser{data: data, pos: 0}

	id, err := p.readUint16()
	if err != nil {
		return nil, err
	}
	if id != reqID {
		return nil, fmt.Errorf("id mismatch")
	}

	flags, _ := p.readUint16()
	qdCount, _ := p.readUint16()
	anCount, _ := p.readUint16()

	if err := p.skip(4); err != nil {
		return nil, err
	}

	rCode := flags & 0x000F
	if rCode != 0 {
		return nil, fmt.Errorf("dns error rcode: %d", rCode)
	}

	for i := 0; i < int(qdCount); i++ {
		if _, err := p.readName(); err != nil {
			return nil, err
		}
		if err := p.skip(4); err != nil {
			return nil, err
		}
	}

	res := &dnsResponse{
		IPs: make([]net.IP, 0, 4)}

	for i := 0; i < int(anCount); i++ {
		_, err := p.readName()
		if err != nil {
			return nil, err
		}

		rType, err := p.readUint16()
		if err != nil {
			return nil, err
		}
		if err := p.skip(6); err != nil {
			return nil, err
		}

		rdLen, err := p.readUint16()
		if err != nil {
			return nil, err
		}

		switch rType {
		case dnsTypeA:
			if rdLen == 4 {
				if p.pos+4 > len(p.data) {
					return nil, ErrInvalidResp
				}
				ip := make(net.IP, 4)
				copy(ip, p.data[p.pos:p.pos+4])
				res.IPs = append(res.IPs, ip)
				p.pos += 4
			} else {
				p.skip(int(rdLen))
			}
		case dnsTypeAAAA:
			if rdLen == 16 {
				if p.pos+16 > len(p.data) {
					return nil, ErrInvalidResp
				}
				ip := make(net.IP, 16)
				copy(ip, p.data[p.pos:p.pos+16])
				res.IPs = append(res.IPs, ip)
				p.pos += 16
			} else {
				p.skip(int(rdLen))
			}
		case dnsTypeCNAME:
			cname, err := p.readName()
			if err == nil && res.CNAME == "" {
				res.CNAME = cname
			}
		default:
			p.skip(int(rdLen))
		}
	}

	return res, nil
}
