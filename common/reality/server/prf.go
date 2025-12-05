package reality

import (
	"errors"
)

func noEKMBecauseRenegotiation(label string, context []byte, length int) ([]byte, error) {
	return nil, errors.New("crypto/tls: ExportKeyingMaterial is unavailable when renegotiation is enabled")
}

func noEKMBecauseNoEMS(_ string, _ []byte, _ int) ([]byte, error) {
	return nil, errors.New("crypto/tls: ExportKeyingMaterial is unavailable when neither TLS 1.3 nor Extended Master Secret are negotiated; override with GODEBUG=tlsunsafeekm=1")
}
