package common

import (
	"net"
)

type PeekedConn struct {
	net.Conn
	InitialData []byte
}

func (p *PeekedConn) Read(b []byte) (n int, err error) {
	if len(p.InitialData) > 0 {
		n = copy(b, p.InitialData)
		p.InitialData = p.InitialData[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}
