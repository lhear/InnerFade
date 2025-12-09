package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

type doTClient struct {
	addr      string
	tlsConfig *tls.Config

	connLock sync.Mutex
	conn     *tls.Conn
	closed   bool

	reqLock  sync.Mutex
	requests map[uint16]chan exchangeResult
}

func newDoTClient(addr string, dnsHost string) *doTClient {
	return &doTClient{
		addr: addr,
		tlsConfig: &tls.Config{
			ServerName: dnsHost,
			MinVersion: tls.VersionTLS12,
		},
		requests: make(map[uint16]chan exchangeResult),
	}
}

func (c *doTClient) close() {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	c.closed = true
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.reqLock.Lock()
	defer c.reqLock.Unlock()
	for _, ch := range c.requests {
		ch <- exchangeResult{err: ErrConnClosed}
		close(ch)
	}
}

func (c *doTClient) getConn() (*tls.Conn, bool, error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	if c.closed {
		return nil, false, ErrConnClosed
	}
	if c.conn != nil {
		return c.conn, false, nil
	}

	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", c.addr, c.tlsConfig)
	if err != nil {
		return nil, false, err
	}

	c.conn = conn
	go c.readLoop(conn)

	return conn, true, nil
}

func (c *doTClient) closeConn(target *tls.Conn) {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	if c.conn == target {
		_ = c.conn.Close()
		c.conn = nil
	}
}

func (c *doTClient) readLoop(conn *tls.Conn) {
	defer c.closeConn(conn)
	lenBuf := make([]byte, 2)
	buf := make([]byte, maxBufferSize)

	for {
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			c.dispatchError(err)
			return
		}
		l := int(binary.BigEndian.Uint16(lenBuf))
		if l > cap(buf) {
			buf = make([]byte, l)
		}
		msgBuf := buf[:l]
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
			c.dispatchError(err)
			return
		}

		if l < 2 {
			continue
		}
		id := binary.BigEndian.Uint16(msgBuf[:2])

		respCopy := make([]byte, len(msgBuf))
		copy(respCopy, msgBuf)

		resp, err := parseResponse(respCopy, id)

		c.reqLock.Lock()
		ch, ok := c.requests[id]
		if ok {
			delete(c.requests, id)
		}
		c.reqLock.Unlock()

		if ok {
			ch <- exchangeResult{res: resp, err: err}
			close(ch)
		}
	}
}

func (c *doTClient) dispatchError(err error) {
	c.reqLock.Lock()
	defer c.reqLock.Unlock()
	for id, ch := range c.requests {
		ch <- exchangeResult{err: err}
		close(ch)
		delete(c.requests, id)
	}
}

func (c *doTClient) exchange(ctx context.Context, reqData []byte, id uint16) (*dnsResponse, error) {
	conn, _, err := c.getConn()
	if err != nil {
		return nil, err
	}

	resCh := make(chan exchangeResult, 1)
	c.reqLock.Lock()
	c.requests[id] = resCh
	c.reqLock.Unlock()

	defer func() {
		c.reqLock.Lock()
		delete(c.requests, id)
		c.reqLock.Unlock()
	}()

	l := len(reqData)
	fullMsg := make([]byte, 2+l)
	binary.BigEndian.PutUint16(fullMsg[0:2], uint16(l))
	copy(fullMsg[2:], reqData)

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
	} else {
		_ = conn.SetWriteDeadline(time.Now().Add(defaultTimeout))
	}

	if _, err := conn.Write(fullMsg); err != nil {
		c.closeConn(conn)
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		return res.res, res.err
	}
}
