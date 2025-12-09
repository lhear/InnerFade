package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

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
