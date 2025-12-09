package dns

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dnsPort        = "53"
	doTPort        = "853"
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
	ErrConnClosed   = errors.New("connection closed")
)

var bufferPool = sync.Pool{
	New: func() any {
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

type dnsResponse struct {
	IPs   []net.IP
	CNAME string
}

type exchangeResult struct {
	res *dnsResponse
	err error
}

type dnsExchanger interface {
	exchange(ctx context.Context, reqData []byte, id uint16) (*dnsResponse, error)
	close()
}
