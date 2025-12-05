//go:build !boringcrypto

package reality

var (
	allowedSupportedVersionsFIPS = []uint16{
		VersionTLS12,
		VersionTLS13,
	}
	allowedSignatureAlgorithmsFIPS = []SignatureScheme{
		PSSWithSHA256,
		ECDSAWithP256AndSHA256,
		Ed25519,
		PSSWithSHA384,
		PSSWithSHA512,
		PKCS1WithSHA256,
		PKCS1WithSHA384,
		PKCS1WithSHA512,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512,
	}
)
