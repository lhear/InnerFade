package server

import (
	"context"
	"fmt"
	"net"
	"time"
)

func (s *Server) dialHappyEyeballs(ctx context.Context, host, port string) (net.Conn, error) {
	ipAddrs, err := s.dnsResolver.LookupIP(ctx, host)
	if err != nil {
		return nil, err
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}
	results := make(chan dialResult)

	ctxDial, cancel := context.WithCancel(ctx)
	defer cancel()

	pending := 0
	const happyEyeballsDelay = 250 * time.Millisecond
	var lastErr error

	for i, ip := range ipAddrs {
		targetAddr := net.JoinHostPort(ip.String(), port)
		pending++

		go func(addr string) {
			conn, err := s.dialTCP(ctxDial, addr)
			select {
			case results <- dialResult{conn, err}:
			case <-ctxDial.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}(targetAddr)

		if i == len(ipAddrs)-1 {
			break
		}

		timer := time.NewTimer(happyEyeballsDelay)
		select {
		case res := <-results:
			timer.Stop()
			if res.err == nil {
				return res.conn, nil
			}
			lastErr = res.err
			pending--
		case <-timer.C:
		}
	}

	for pending > 0 {
		res := <-results
		if res.err == nil {
			return res.conn, nil
		}
		lastErr = res.err
		pending--
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all dials failed, last error: %v", lastErr)
	}
	return nil, fmt.Errorf("failed to dial %v: no successful connection", ipAddrs)
}

func (s *Server) dialTCP(ctx context.Context, address string) (net.Conn, error) {
	if s.config.Socks5Proxy != "" {
		return s.proxyDialer.Dial("tcp", address)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", address)
}
