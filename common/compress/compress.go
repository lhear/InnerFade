//go:generate go run gen.go

package compress

import (
	"errors"
	"fmt"
	"math/bits"
	"strings"
)

const (
	base        = 38
	max3Char    = base * base * base
	max2Char    = base * base
	max1Char    = base
	offset2Char = max3Char
	offset1Char = offset2Char + max2Char
	offsetDict  = offset1Char + max1Char
)

func getTrieChild(nodeIdx uint32, charIdx int8) (uint32, bool) {
	node := &trieNodes[nodeIdx]
	bit := uint64(1) << uint64(charIdx)
	if node.mask&bit == 0 {
		return 0, false
	}
	childOffset := bits.OnesCount64(node.mask & (bit - 1))
	return node.childrenBase + uint32(childOffset), true
}

func Compress(domain string) ([]byte, error) {
	n := len(domain)
	buf := make([]byte, 0, n)
	i := 0
	for i < n {
		matchedLen := 0
		var matchedCode uint16
		currNodeIdx := uint32(0)
		for k := i; k < n; k++ {
			charIdx := charToIdxTable[domain[k]]
			if charIdx < 0 {
				return nil, fmt.Errorf("invalid character '%c' at index %d", domain[k], k)
			}
			nextIdx, exists := getTrieChild(currNodeIdx, charIdx)
			if !exists {
				break
			}
			currNodeIdx = nextIdx
			if trieNodes[currNodeIdx].isEnd {
				matchedLen = k - i + 1
				matchedCode = trieNodes[currNodeIdx].code
			}
		}
		if matchedLen > 0 {
			buf = append(buf, byte(matchedCode>>8), byte(matchedCode))
			i += matchedLen
			continue
		}
		remaining := n - i
		v1 := int(charToIdxTable[domain[i]])
		if v1 < 0 {
			return nil, fmt.Errorf("invalid character '%c' at index %d", domain[i], i)
		}
		if remaining >= 3 {
			v2 := int(charToIdxTable[domain[i+1]])
			v3 := int(charToIdxTable[domain[i+2]])
			if v2 < 0 || v3 < 0 {
				return nil, fmt.Errorf("invalid character sequence at index %d", i)
			}
			val := uint16(v1*max2Char + v2*max1Char + v3)
			buf = append(buf, byte(val>>8), byte(val))
			i += 3
		} else if remaining == 2 {
			v2 := int(charToIdxTable[domain[i+1]])
			if v2 < 0 {
				return nil, fmt.Errorf("invalid character at index %d", i+1)
			}
			val := uint16(offset2Char + v1*max1Char + v2)
			buf = append(buf, byte(val>>8), byte(val))
			i += 2
		} else {
			val := uint16(offset1Char + v1)
			buf = append(buf, byte(val>>8), byte(val))
			i += 1
		}
	}
	return buf, nil
}

func Decompress(data []byte) (string, error) {
	if len(data)%2 != 0 {
		return "", errors.New("invalid data length: must be even")
	}
	var sb strings.Builder
	sb.Grow(len(data) * 2)
	for i := 0; i < len(data); i += 2 {
		code := uint16(data[i])<<8 | uint16(data[i+1])
		if code < offset2Char {
			v1 := code / max2Char
			rem := code % max2Char
			v2 := rem / max1Char
			v3 := rem % max1Char
			sb.WriteByte(idxToCharTable[v1])
			sb.WriteByte(idxToCharTable[v2])
			sb.WriteByte(idxToCharTable[v3])
		} else if code < offset1Char {
			val := code - offset2Char
			v1 := val / base
			v2 := val % base
			sb.WriteByte(idxToCharTable[v1])
			sb.WriteByte(idxToCharTable[v2])
		} else if code < offsetDict {
			val := code - offset1Char
			sb.WriteByte(idxToCharTable[val])
		} else {
			dictIdx := int(code - offsetDict)
			if dictIdx < len(dictList) {
				sb.WriteString(dictList[dictIdx])
			} else {
				return "", fmt.Errorf("unknown dictionary code: %d", code)
			}
		}
	}
	return sb.String(), nil
}
