package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ECSResolver struct {
	Upstream   string
	Timeout    time.Duration
	MaxRetries int
	clientIP   net.IP
	preferIPv6 bool
	cache      *resolverCache
	sf         singleflightGroup

	exchanger dnsExchanger
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
	var exchanger dnsExchanger

	if port == doTPort {
		exchanger = newDoTClient(normalizedUpstream, host)
	} else {
		uc, err := newUDPClient(normalizedUpstream)
		if err != nil {
			return nil, fmt.Errorf("failed to init udp client: %w", err)
		}
		exchanger = uc
	}

	return &ECSResolver{
		Upstream:   normalizedUpstream,
		Timeout:    defaultTimeout,
		MaxRetries: maxRetries,
		clientIP:   clientIP,
		cache:      newCache(),
		preferIPv6: preferIPv6,
		exchanger:  exchanger,
	}, nil
}

func (r *ECSResolver) Close() {
	if r.cache != nil {
		r.cache.close()
	}
	if r.exchanger != nil {
		r.exchanger.close()
	}
}

func (r *ECSResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if host == "" {
		return nil, errors.New("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
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

	return r.exchanger.exchange(ctx, reqData, id)
}