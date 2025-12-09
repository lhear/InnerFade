package dns

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

type udpClient struct {
	conn    *net.UDPConn
	reqLock sync.Mutex
	reqs    map[uint16]chan exchangeResult
	closed  chan struct{}
}

func newUDPClient(addr string) (*udpClient, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}

	c := &udpClient{
		conn:   conn.(*net.UDPConn),
		reqs:   make(map[uint16]chan exchangeResult),
		closed: make(chan struct{}),
	}

	_ = c.conn.SetReadBuffer(1024 * 1024)
	_ = c.conn.SetWriteBuffer(1024 * 1024)

	go c.readLoop()
	return c, nil
}

func (c *udpClient) close() {
	select {
	case <-c.closed:
		return
	default:
		close(c.closed)
	}
	_ = c.conn.Close()

	c.reqLock.Lock()
	defer c.reqLock.Unlock()
	for _, ch := range c.reqs {
		ch <- exchangeResult{err: ErrConnClosed}
		close(ch)
	}
	c.reqs = nil
}

func (c *udpClient) readLoop() {
	buf := make([]byte, maxBufferSize)

	for {
		select {
		case <-c.closed:
			return
		default:
		}

		n, err := c.conn.Read(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}

		if n < 2 {
			continue
		}

		respData := make([]byte, n)
		copy(respData, buf[:n])

		id := binary.BigEndian.Uint16(respData[:2])

		c.reqLock.Lock()
		ch, ok := c.reqs[id]
		if ok {
			delete(c.reqs, id)
		}
		c.reqLock.Unlock()

		if ok {
			resp, parseErr := parseResponse(respData, id)
			ch <- exchangeResult{res: resp, err: parseErr}
			close(ch)
		}
	}
}

func (c *udpClient) exchange(ctx context.Context, reqData []byte, id uint16) (*dnsResponse, error) {
	resCh := make(chan exchangeResult, 1)

	c.reqLock.Lock()
	if c.reqs == nil {
		c.reqLock.Unlock()
		return nil, ErrConnClosed
	}
	c.reqs[id] = resCh
	c.reqLock.Unlock()

	defer func() {
		c.reqLock.Lock()
		if c.reqs != nil {
			delete(c.reqs, id)
		}
		c.reqLock.Unlock()
	}()

	_ = c.conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := c.conn.Write(reqData); err != nil {
		return nil, err
	}
	_ = c.conn.SetWriteDeadline(time.Time{})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		return res.res, res.err
	}
}
