# InnerFade: Stealthy TLS MITM Proxy Powered by REALITY
InnerFade is a network proxy tool that leverages the [REALITY](https://github.com/XTLS/REALITY) protocol for secure communication. It performs TLS Man-in-the-Middle (MITM) decryption on the client and forwards traffic via REALITY. Its key innovation is embedding target address information into the TLS handshake's SessionId, which enables highly effective traffic obfuscation and zero-packet target resolution.

## Key Features
*   Client-side TLS MITM decryption with dynamic certificate generation.
*   ALPN passthrough for enhanced compatibility.
*   High-performance, file-backed domain caching on both client and server.
*   Stealthy transfer of target domain ID, port, and ALPN via encrypted TLS `ClientHello.SessionId`.
*   Zero-packet target resolution on the server, eliminating extra metadata.

## Getting Started
Requires Go 1.24+.
1.  **Build:** `go build -ldflags "-s -w" -o innerfade ./cmd`
2.  **Configuration:** Use separate client/server JSON config files (see `examples/`).
3.  **Generate Keys & CA:**
    *   X25519 Key Pair: `./innerfade -generate-keypair`
    *   MITM CA Cert/Key: `./innerfade -generate-ca -ca-cert ca.crt -ca-key ca.key` (CA must be trusted by client).
4.  **Run:** `./innerfade -c config.json`

## Security Considerations
*   Retaining the cache is crucial for minimizing traffic characteristics.
*   Client-side MITM requires full trust in the tool and operator; protect the X25519 private key diligently.
*   Always verify the source and integrity of the InnerFade executable.