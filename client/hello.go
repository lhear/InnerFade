package client

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"innerfade/common"
	"innerfade/logger"
)

func (c *Client) peekClientHello(conn net.Conn) (net.Conn, string, []string, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, "", nil, err
	}

	if header[0] != 0x16 {
		return nil, "", nil, fmt.Errorf("not a TLS handshake: 0x%x", header[0])
	}

	length := int(header[3])<<8 | int(header[4])

	if length > 65535 {
		return nil, "", nil, fmt.Errorf("TLS record too large: %d", length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, "", nil, err
	}

	sni, alpns := parseClientHelloDetails(body)
	logger.Debugf("[%s] peeked ClientHello - SNI: %s, ALPNs: %v", conn.RemoteAddr(), sni, alpns)

	payload := make([]byte, 0, 5+length)
	payload = append(payload, header...)
	payload = append(payload, body...)

	return &common.PeekedConn{Conn: conn, InitialData: payload}, sni, alpns, nil
}

func (c *Client) createTLSConfigWithALPNs(hostname string, alpns []string) *tls.Config {
	cert, _ := c.certCache.Get(hostname, c.ca)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
		NextProtos:   alpns,
	}
}

func parseClientHelloDetails(data []byte) (sni string, alpns []string) {
	if len(data) < 44 {
		return "", nil
	}
	if data[0] != 0x01 {
		return "", nil
	}

	offset := 6
	offset += 32

	if offset >= len(data) {
		return "", nil
	}

	sessionIDLen := int(data[offset])
	offset++
	offset += sessionIDLen
	if offset >= len(data) {
		return "", nil
	}

	if offset+2 > len(data) {
		return "", nil
	}
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen
	if offset >= len(data) {
		return "", nil
	}

	if offset+1 > len(data) {
		return "", nil
	}
	compLen := int(data[offset])
	offset += 1 + compLen
	if offset >= len(data) {
		return "", nil
	}

	if offset+2 > len(data) {
		return "", nil
	}
	extTotalLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	end := offset + extTotalLen
	if end > len(data) {
		end = len(data)
	}

	for offset+4 <= end {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		extEnd := offset + extLen
		if extEnd > end {
			break
		}

		switch extType {
		case 0x0000:
			if offset+2 <= extEnd {
				listLen := int(data[offset])<<8 | int(data[offset+1])
				sniOffset := offset + 2
				sniEnd := sniOffset + listLen
				if sniEnd > extEnd {
					sniEnd = extEnd
				}

				for sniOffset+3 <= sniEnd {
					nameType := data[sniOffset]
					nameLen := int(data[sniOffset+1])<<8 | int(data[sniOffset+2])
					sniOffset += 3
					if sniOffset+nameLen <= sniEnd {
						if nameType == 0x00 {
							sni = string(data[sniOffset : sniOffset+nameLen])
							break
						}
					}
					sniOffset += nameLen
				}
			}

		case 0x0010:
			if offset+2 <= extEnd {
				listLen := int(data[offset])<<8 | int(data[offset+1])
				alpnOffset := offset + 2
				alpnEnd := alpnOffset + listLen
				if alpnEnd > extEnd {
					alpnEnd = extEnd
				}

				for alpnOffset < alpnEnd {
					if alpnOffset+1 > alpnEnd {
						break
					}
					pLen := int(data[alpnOffset])
					alpnOffset++

					if alpnOffset+pLen <= alpnEnd {
						alpns = append(alpns, string(data[alpnOffset:alpnOffset+pLen]))
					}
					alpnOffset += pLen
				}
			}
		}
		offset = extEnd
	}

	return sni, alpns
}
