package compress

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	charset = "abcdefghijklmnopqrstuvwxyz0123456789-."
	base    = 38
)

const (
	max3Char    = base * base * base
	max2Char    = base * base
	max1Char    = base
	offset2Char = max3Char
	offset1Char = offset2Char + max2Char
	offsetDict  = offset1Char + max1Char
)

type trieNode struct {
	children [base]*trieNode
	code     uint16
	isEnd    bool
}

var (
	charToIdxTable [256]int8
	idxToCharTable [base]byte
	dictList       []string
	trieRoot       *trieNode
)

func init() {
	for i := 0; i < 256; i++ {
		charToIdxTable[i] = -1
	}
	for i := 0; i < len(charset); i++ {
		c := charset[i]
		idx := int8(i)
		charToIdxTable[c] = idx
		idxToCharTable[i] = c
		if c >= 'a' && c <= 'z' {
			charToIdxTable[c-32] = idx
		}
	}
	maxDictCapacity := 65536 - offsetDict
	if len(commonDict) > maxDictCapacity {
		panic(fmt.Sprintf("Dictionary size (%d) exceeds remaining coding space (%d)", len(commonDict), maxDictCapacity))
	}
	sortedDict := make([]string, len(commonDict))
	copy(sortedDict, commonDict)
	sort.Slice(sortedDict, func(i, j int) bool {
		return len(sortedDict[i]) > len(sortedDict[j])
	})
	dictList = sortedDict
	trieRoot = &trieNode{}
	for i, s := range sortedDict {
		code := uint16(offsetDict + i)
		addStringToTrie(trieRoot, s, code)
	}
}

func addStringToTrie(root *trieNode, s string, code uint16) {
	node := root
	for i := 0; i < len(s); i++ {
		charIdx := charToIdxTable[s[i]]
		if charIdx < 0 {
			continue
		}
		if node.children[charIdx] == nil {
			node.children[charIdx] = &trieNode{}
		}
		node = node.children[charIdx]
	}
	if !node.isEnd {
		node.isEnd = true
		node.code = code
	}
}

func Compress(domain string) ([]byte, error) {
	n := len(domain)
	buf := make([]byte, 0, n)
	i := 0
	for i < n {
		matchedLen := 0
		var matchedCode uint16
		node := trieRoot
		for k := i; k < n; k++ {
			charIdx := charToIdxTable[domain[k]]
			if charIdx < 0 {
				return nil, fmt.Errorf("invalid character '%c' at index %d", domain[k], k)
			}
			node = node.children[charIdx]
			if node == nil {
				break
			}
			if node.isEnd {
				matchedLen = k - i + 1
				matchedCode = node.code
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
