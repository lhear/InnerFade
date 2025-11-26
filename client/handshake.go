package client

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"

	"innerfade/common"
)

func (c *Client) handshakeServer(conn net.Conn, hostname string, port int, alpns []string) ([]string, error) {
	alpnCode, ok := common.AlpnToByte(alpns)
	if !ok {

		alpnCode = 0x00
	}

	baseSize := 1 + len(hostname) + 2 + 1 + 1
	minTarget, maxTarget := 150, 350
	currentSize := baseSize + 2

	var paddingLen int
	if currentSize < minTarget {
		diff := minTarget - currentSize
		extra := secureRandomInt(maxTarget - minTarget)
		paddingLen = diff + extra
		if currentSize+paddingLen > maxTarget {
			paddingLen = maxTarget - currentSize
		}
	} else if currentSize < maxTarget {
		remaining := maxTarget - currentSize
		if remaining > 0 {
			paddingLen = secureRandomInt(remaining)
		}
	}

	if paddingLen < 0 {
		paddingLen = 0
	}

	buf := make([]byte, 0, currentSize+paddingLen)
	buf = append(buf, byte(len(hostname)))
	buf = append(buf, hostname...)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	buf = append(buf, portBytes...)
	buf = append(buf, alpnCode)

	padLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(padLenBytes, uint16(paddingLen))
	buf = append(buf, padLenBytes...)
	buf = append(buf, make([]byte, paddingLen)...)

	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}

	return c.readServerALPNResponse(conn)
}

func (c *Client) readServerALPNResponse(conn net.Conn) ([]string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] == 1 {
		return nil, fmt.Errorf("upstream connection rejected")
	}

	alpns, ok := common.ByteToAlpn(header[1])
	if !ok {
		return nil, fmt.Errorf("failed to parse ALPN")
	}

	paddingLen := int(binary.BigEndian.Uint16(header[2:4]))
	if paddingLen > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(paddingLen)); err != nil {
			return nil, err
		}
	}

	return alpns, nil
}

func secureRandomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}
