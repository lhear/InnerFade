package compress

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const charset = "abcdefghijklmnopqrstuvwxyz0123456789-."
const base = 38

const (
	max3Char    = base * base * base
	max2Char    = base * base
	max1Char    = base
	offset2Char = max3Char
	offset1Char = offset2Char + max2Char
	offsetDict  = offset1Char + max1Char
)

var commonDict = []string{
	".com", ".net", ".org", ".edu", ".gov",
	".mil", ".int", ".top", ".xyz", ".vip",
	"www.", "wap.", "api.", "blog.", "mail.",
	"google", "apple", "image", "video",
	"document", "shop", "cloud", "static",
	"source", "book", "mark", "play",
	"voice", "visit", "chat", "studio", "profile",
	"assets", "content", "user", "-api", "-cdn",
	"online", "open", "help", "dashboard",
	"amazon", "fast", "web.", "project",
	"state", "login", "client", "speed", "test",
	"microsoft", "live", "mozilla", "storage",
}

var (
	charToIdxTable [256]int8
	idxToCharTable [base]byte
	dictBytes      [][]byte
	dictCodes      []uint16
	idxToDict      map[uint16]string
)

func init() {
	for i := 0; i < 256; i++ {
		charToIdxTable[i] = -1
	}
	for i := 0; i < len(charset); i++ {
		c := charset[i]
		charToIdxTable[c] = int8(i)
		idxToCharTable[i] = c
	}
	maxDictCapacity := 65536 - offsetDict
	if len(commonDict) > maxDictCapacity {
		panic("Dictionary size exceeds remaining coding space")
	}
	sort.Slice(commonDict, func(i, j int) bool {
		return len(commonDict[i]) > len(commonDict[j])
	})
	dictBytes = make([][]byte, len(commonDict))
	dictCodes = make([]uint16, len(commonDict))
	idxToDict = make(map[uint16]string, len(commonDict))
	for i, s := range commonDict {
		code := uint16(offsetDict + i)
		dictBytes[i] = []byte(s)
		dictCodes[i] = code
		idxToDict[code] = s
	}
}

func Compress(domain string) ([]byte, error) {
	domain = strings.ToLower(domain)
	n := len(domain)
	buf := make([]byte, 0, n/2+2)
	i := 0
	for i < n {
		matchFound := false
		currentStr := domain[i:]
		for k, dBytes := range dictBytes {
			dLen := len(dBytes)
			if len(currentStr) >= dLen {
				if currentStr[:dLen] == string(dBytes) {
					code := dictCodes[k]
					buf = append(buf, byte(code>>8), byte(code))
					i += dLen
					matchFound = true
					break
				}
			}
		}
		if matchFound {
			continue
		}
		remaining := n - i
		if remaining >= 3 {
			v1 := charToIdxTable[domain[i]]
			v2 := charToIdxTable[domain[i+1]]
			v3 := charToIdxTable[domain[i+2]]
			if v1 < 0 || v2 < 0 || v3 < 0 {
				return nil, fmt.Errorf("invalid character at index %d", i)
			}
			val := uint16(int(v1)*max2Char + int(v2)*max1Char + int(v3))
			buf = append(buf, byte(val>>8), byte(val))
			i += 3
			continue
		}
		if remaining == 2 {
			v1 := charToIdxTable[domain[i]]
			v2 := charToIdxTable[domain[i+1]]
			if v1 < 0 || v2 < 0 {
				return nil, fmt.Errorf("invalid character at index %d", i)
			}
			val := uint16(offset2Char + int(v1)*max1Char + int(v2))
			buf = append(buf, byte(val>>8), byte(val))
			i += 2
			continue
		}

		if remaining == 1 {
			v1 := charToIdxTable[domain[i]]
			if v1 < 0 {
				return nil, fmt.Errorf("invalid character at index %d", i)
			}
			val := uint16(offset1Char + int(v1))
			buf = append(buf, byte(val>>8), byte(val))
			i += 1
			continue
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
			sb.WriteByte(idxToCharTable[code/max2Char])
			sb.WriteByte(idxToCharTable[(code/max1Char)%base])
			sb.WriteByte(idxToCharTable[code%base])
		} else if code < offset1Char {
			val := code - offset2Char
			sb.WriteByte(idxToCharTable[val/base])
			sb.WriteByte(idxToCharTable[val%base])
		} else if code < offsetDict {
			val := code - offset1Char
			sb.WriteByte(idxToCharTable[val])
		} else {
			if s, ok := idxToDict[code]; ok {
				sb.WriteString(s)
			} else {
				return "", fmt.Errorf("unknown dictionary code: %d", code)
			}
		}
	}
	return sb.String(), nil
}
