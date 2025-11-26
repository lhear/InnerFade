package common

import (
	"io"
	"net"
	"sync"
)

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 16*1024)
		return &b
	},
}

func TransferData(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	wg.Add(2)

	streamCopy := func(dst, src net.Conn) {
		defer wg.Done()

		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		defer bufferPool.Put(bufPtr)

		_, _ = io.CopyBuffer(dst, src, buf)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}

	go streamCopy(b, a)
	go streamCopy(a, b)

	wg.Wait()
}
