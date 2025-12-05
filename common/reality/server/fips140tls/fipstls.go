package fips140tls

import (
	"crypto/fips140"
	"sync/atomic"
)

var required atomic.Bool

func init() {
	if fips140.Enabled() {
		Force()
	}
}

func Force() {
	required.Store(true)
}

func Required() bool {
	return required.Load()
}
