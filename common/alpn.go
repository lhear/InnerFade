package common

const (
	CodeEnd byte = 0x0
	CodeH1  byte = 0x1
	CodeH2  byte = 0x2
)

const SlotsPerByte = 4

func AlpnToByte(alpnList []string) (byte, bool) {
	var combinedByte byte
	count := 0
	for _, alpn := range alpnList {
		if count >= SlotsPerByte {
			break
		}
		var code byte
		switch alpn {
		case "h2":
			code = CodeH2
		case "http/1.1":
			code = CodeH1
		default:
			continue
		}
		shift := (3 - count) * 2
		combinedByte |= (code << shift)
		count++
	}
	return combinedByte, combinedByte != 0
}

func ByteToAlpn(b byte) ([]string, bool) {
	alpnList := make([]string, 0, SlotsPerByte)
	for i := 0; i < SlotsPerByte; i++ {
		shift := (3 - i) * 2
		code := (b >> shift) & 0x3

		if code == CodeEnd {
			break
		}
		switch code {
		case CodeH1:
			alpnList = append(alpnList, "http/1.1")
		case CodeH2:
			alpnList = append(alpnList, "h2")
		default:
			return nil, false
		}
	}
	return alpnList, true
}
