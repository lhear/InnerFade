package dns

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewECSResolver(t *testing.T) {
	tests := []struct {
		input      string
		wantHost   string
		wantClient string
	}{
		{"8.8.8.8", "8.8.8.8:53", "<nil>"},
		{"1.1.1.1:5353", "1.1.1.1:5353", "<nil>"},
		{"8.8.8.8@1.2.3.4", "8.8.8.8:53", "1.2.3.4"},
		{"[2001:db8::1]", "[2001:db8::1]:53", "<nil>"},
		{"[2001:db8::1]:5353", "[2001:db8::1]:5353", "<nil>"},
	}

	for _, tt := range tests {
		r, _ := NewECSResolver(tt.input)
		if r.Upstream != tt.wantHost {
			t.Errorf("NewECSResolver(%q) Upstream = %v, want %v", tt.input, r.Upstream, tt.wantHost)
		}
		if tt.wantClient == "<nil>" {
			if r.clientIP != nil {
				t.Errorf("NewECSResolver(%q) clientIP = %v, want nil", tt.input, r.clientIP)
			}
		} else {
			if r.clientIP.String() != tt.wantClient {
				t.Errorf("NewECSResolver(%q) clientIP = %v, want %v", tt.input, r.clientIP, tt.wantClient)
			}
		}
	}
}

func TestReorderIPs(t *testing.T) {
	ipv4 := net.ParseIP("1.1.1.1")
	ipv6 := net.ParseIP("2001:db8::1")

	tests := []struct {
		name       string
		ips        []net.IP
		preferIPv6 bool
		wantFirst  net.IP
	}{
		{"Mix Prefer V4", []net.IP{ipv6, ipv4}, false, ipv4},
		{"Mix Prefer V6", []net.IP{ipv4, ipv6}, true, ipv6},
		{"Only V4 Prefer V6", []net.IP{ipv4}, true, ipv4},
		{"Only V6 Prefer V4", []net.IP{ipv6}, false, ipv6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := make([]net.IP, len(tt.ips))
			copy(input, tt.ips)

			reorderIPs(input, tt.preferIPv6)

			if len(input) > 0 && !input[0].Equal(tt.wantFirst) {
				t.Errorf("reorderIPs() first = %v, want %v", input[0], tt.wantFirst)
			}
		})
	}
}

func TestBuildECSData(t *testing.T) {
	ip4 := net.ParseIP("1.2.3.4")
	data, err := buildECSData(ip4)
	if err != nil {
		t.Fatalf("buildECSData failed: %v", err)
	}
	if len(data) != 7 {
		t.Errorf("IPv4 ECS data len = %d, want 7", len(data))
	}
	if data[2] != 24 {
		t.Errorf("IPv4 prefix len = %d, want 24", data[2])
	}

	ip6 := net.ParseIP("2001:db8::1")
	data6, err := buildECSData(ip6)
	if err != nil {
		t.Fatalf("buildECSData ipv6 failed: %v", err)
	}
	if len(data6) != 11 {
		t.Errorf("IPv6 ECS data len = %d, want 11", len(data6))
	}
	if data6[2] != 56 {
		t.Errorf("IPv6 prefix len = %d, want 56", data6[2])
	}
}

type mockDNSServer struct {
	conn       *net.UDPConn
	addr       string
	reqCount   int32
	handleFunc func(req []byte, addr net.Addr) []byte
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

func startMockServer(t *testing.T, handler func(req []byte, addr net.Addr) []byte) *mockDNSServer {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve addr failed: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp failed: %v", err)
	}

	s := &mockDNSServer{
		conn:       conn,
		addr:       conn.LocalAddr().String(),
		handleFunc: handler,
		stopCh:     make(chan struct{}),
	}

	s.wg.Add(1)
	go s.serve()
	return s
}

func (s *mockDNSServer) serve() {
	defer s.wg.Done()
	buf := make([]byte, 1024)
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, remoteAddr, err := s.conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		atomic.AddInt32(&s.reqCount, 1)
		reqData := make([]byte, n)
		copy(reqData, buf[:n])

		go func(req []byte, rAddr net.Addr) {
			resp := s.handleFunc(req, rAddr)
			if resp != nil {
				s.conn.WriteTo(resp, rAddr)
			}
		}(reqData, remoteAddr)
	}
}

func (s *mockDNSServer) Close() {
	close(s.stopCh)
	s.conn.Close()
	s.wg.Wait()
}

func buildMockResponse(req []byte, qType uint16, answerIP net.IP, cnameTarget string) []byte {
	if len(req) < 2 {
		return nil
	}
	id := binary.BigEndian.Uint16(req[0:2])

	resp := make([]byte, 0, 512)
	resp = binary.BigEndian.AppendUint16(resp, id)
	resp = binary.BigEndian.AppendUint16(resp, 0x8180)
	resp = binary.BigEndian.AppendUint16(resp, 1)
	resp = binary.BigEndian.AppendUint16(resp, 1)
	resp = binary.BigEndian.AppendUint16(resp, 0)
	resp = binary.BigEndian.AppendUint16(resp, 0)
	pos := 12
	for pos < len(req) {
		b := req[pos]
		pos++
		if b == 0 {
			break
		}
		pos += int(b)
	}
	pos += 4
	resp = append(resp, req[12:pos]...)

	resp = binary.BigEndian.AppendUint16(resp, 0xC00C)

	if cnameTarget != "" {
		resp = binary.BigEndian.AppendUint16(resp, dnsTypeCNAME)
		resp = binary.BigEndian.AppendUint16(resp, dnsClassIN)
		resp = binary.BigEndian.AppendUint32(resp, 300)
		rdata, _ := appendDomainName([]byte{}, cnameTarget)
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(rdata)))
		resp = append(resp, rdata...)
	} else {
		resp = binary.BigEndian.AppendUint16(resp, qType)
		resp = binary.BigEndian.AppendUint16(resp, dnsClassIN)
		resp = binary.BigEndian.AppendUint32(resp, 300)
		if ip4 := answerIP.To4(); ip4 != nil {
			resp = binary.BigEndian.AppendUint16(resp, 4)
			resp = append(resp, ip4...)
		} else {
			resp = binary.BigEndian.AppendUint16(resp, 16)
			resp = append(resp, answerIP.To16()...)
		}
	}

	return resp
}

func TestResolver_BasicLookup(t *testing.T) {
	targetIP := net.ParseIP("192.168.1.100")
	targetHost := "test.example.com."

	server := startMockServer(t, func(req []byte, addr net.Addr) []byte {
		qType := binary.BigEndian.Uint16(req[len(req)-4 : len(req)-2])
		if qType == dnsTypeA {
			return buildMockResponse(req, dnsTypeA, targetIP, "")
		}
		return nil
	})
	defer server.Close()

	r, _ := NewECSResolver(server.addr)
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, err := r.LookupIP(ctx, targetHost)
	if err != nil {
		t.Fatalf("LookupIP failed: %v", err)
	}

	if len(ips) == 0 {
		t.Fatal("Expected IPs, got none")
	}
	if !ips[0].Equal(targetIP) {
		t.Errorf("Got IP %v, want %v", ips[0], targetIP)
	}
}

func TestResolver_CNAME_Recursion(t *testing.T) {
	mockData := map[string]struct {
		typ string
		val string
	}{
		"alias.com":  {"CNAME", "target.com"},
		"target.com": {"IP", "1.1.1.1"},
	}

	server := startMockServer(t, func(req []byte, addr net.Addr) []byte {
		p := &dnsParser{data: req, pos: 12}
		name, _ := p.readName()
		qType := binary.BigEndian.Uint16(req[len(req)-4 : len(req)-2])

		key := strings.TrimSuffix(name, ".")

		if data, ok := mockData[key]; ok {
			if data.typ == "CNAME" {
				return buildMockResponse(req, qType, nil, data.val)
			} else if data.typ == "IP" && qType == dnsTypeA {
				return buildMockResponse(req, qType, net.ParseIP(data.val), "")
			}
		}
		return nil
	})
	defer server.Close()

	r, _ := NewECSResolver(server.addr)
	ips, err := r.LookupIP(context.Background(), "alias.com")
	if err != nil {
		t.Fatalf("CNAME lookup failed: %v", err)
	}
	if len(ips) == 0 || !ips[0].Equal(net.ParseIP("1.1.1.1")) {
		t.Errorf("CNAME resolution failed, got %v", ips)
	}
}

func TestResolver_Cache_Singleflight(t *testing.T) {
	targetIP := net.ParseIP("10.0.0.1")

	server := startMockServer(t, func(req []byte, addr net.Addr) []byte {
		time.Sleep(50 * time.Millisecond)
		qType := binary.BigEndian.Uint16(req[len(req)-4 : len(req)-2])
		if qType == dnsTypeA {
			return buildMockResponse(req, dnsTypeA, targetIP, "")
		}
		return nil
	})
	defer server.Close()

	r, _ := NewECSResolver(server.addr)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.LookupIP(context.Background(), "concurrent.com")
			if err != nil {
				t.Errorf("Lookup failed: %v", err)
			}
		}()
	}
	wg.Wait()

	count := atomic.LoadInt32(&server.reqCount)
	if count > 5 {
		t.Errorf("Too many requests to server: %d (expected singleflight to dedup)", count)
	}

	beforeCache := atomic.LoadInt32(&server.reqCount)
	_, _ = r.LookupIP(context.Background(), "concurrent.com")
	afterCache := atomic.LoadInt32(&server.reqCount)

	if afterCache != beforeCache {
		t.Errorf("Cache miss! Server req count increased from %d to %d", beforeCache, afterCache)
	}
}

func TestResolver_Timeout(t *testing.T) {
	server := startMockServer(t, func(req []byte, addr net.Addr) []byte {
		time.Sleep(200 * time.Millisecond)
		return nil
	})
	defer server.Close()

	r, _ := NewECSResolver(server.addr)
	r.Timeout = 50 * time.Millisecond
	r.MaxRetries = 0
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	start := time.Now()
	_, err := r.LookupIP(ctx, "timeout.com")
	duration := time.Since(start)

	if err == nil {
		t.Fatal("Expected timeout error, got nil")
	}
	if duration > 1*time.Second {
		t.Errorf("Test took too long: %v", duration)
	}
}

func TestResolver_ContextCancel(t *testing.T) {
	server := startMockServer(t, func(req []byte, addr net.Addr) []byte {
		time.Sleep(1 * time.Second)
		return nil
	})
	defer server.Close()

	r, _ := NewECSResolver(server.addr)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := r.LookupIP(ctx, "cancel.com")
	if err == nil {
		t.Fatal("Expected context canceled error, got nil")
	}
	if err != context.Canceled {
		if !strings.Contains(err.Error(), "canceled") {
			t.Errorf("Expected canceled error, got: %v", err)
		}
	}
}

func TestNewECSResolver_Parsing(t *testing.T) {
	tests := []struct {
		input          string
		wantUpstream   string
		wantClientIP   string
		wantPreferIPv6 bool
		wantErr        bool
	}{
		{"8.8.8.8:53@1.2.3.4#true", "8.8.8.8:53", "1.2.3.4", true, false},
		{"8.8.8.8:53@1.2.3.4#1", "8.8.8.8:53", "1.2.3.4", true, false},
		{"8.8.8.8:53@1.2.3.4#false", "8.8.8.8:53", "1.2.3.4", false, false},
		{"8.8.8.8@1.2.3.4", "8.8.8.8:53", "1.2.3.4", false, false},
		{"8.8.8.8#true", "8.8.8.8:53", "<nil>", true, false},
		{"1.1.1.1", "1.1.1.1:53", "<nil>", false, false},
		{"", "", "", false, true},
		{"@1.2.3.4", "", "", false, true},
		{"8.8.8.8#notbool", "", "", false, true},
		{"8.8.8.8@invalidip#true", "", "", false, true},
	}
	for _, tt := range tests {
		r, err := NewECSResolver(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("input %q error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if r.Upstream != tt.wantUpstream {
			t.Errorf("input %q upstream = %v, want %v", tt.input, r.Upstream, tt.wantUpstream)
		}
		if tt.wantClientIP == "<nil>" {
			if r.clientIP != nil {
				t.Errorf("input %q clientIP = %v, want nil", tt.input, r.clientIP)
			}
		} else {
			if r.clientIP.String() != tt.wantClientIP {
				t.Errorf("input %q clientIP = %v, want %v", tt.input, r.clientIP, tt.wantClientIP)
			}
		}
		if r.preferIPv6 != tt.wantPreferIPv6 {
			t.Errorf("input %q preferIPv6 = %v, want %v", tt.input, r.preferIPv6, tt.wantPreferIPv6)
		}
	}
}
