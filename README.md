# InnerFade: A Reality-Based MITM Proxy
InnerFade is a network proxy tool providing secure communication using the **REALITY** protocol. It performs **TLS Man-in-the-Middle (MITM)** decryption on the client side, then forwards traffic via a REALITY connection to a remote server. A key feature is embedding target address data into the TLS handshake's random field upon a domain cache hit, achieving **perfect traffic obfuscation**.

## Features
*  **TLS MITM Decryption:** Client-side decryption of HTTPS traffic by dynamically generating and signing TLS certificates.
*   **Perfect Traffic Feature:**
    *   **ALPN Passthrough:** Transparently passes the client's original ALPN value, resolving compatibility issues common to other MITM proxies.
    *   **Domain Caching:** Employs a high-performance, custom file-backed hash table (using separate index and data files) on both client and server to persistently store domains and their short, SHA256 hash-based IDs.
    *   **Stealthy Target Information Transfer:** Upon a client cache hit, the target domain ID, port, and ALPN code are encrypted and embedded into the 32-byte TLS `ClientHello.Random` field.   
    *   **Zero-Packet Target Resolution:** The server decrypts and extracts this information from the `Random` field upon receiving the `ClientHello`. This resolves the true target address without extra packets or detectable metadata.

## How it Works (High-Level)
1.  **Client-Side Operation:**
    *   For HTTPS, it performs **MITM** decryption using a user-trusted CA. 
    *   It identifies the destination domain, port, and ALPN.
    *   If the domain is in the local cache (**domain cache hit**), it encrypts the domain ID, port, and ALPN using a pre-shared key (derived from X25519) and embeds the encrypted data into the **REALITY connection's `ClientHello.Random` field**.
    *   The client establishes the REALITY connection to the server, forwarding all subsequent traffic.
2.  **Server-Side Operation:**   
    *   It examines the incoming `ClientHello.Random` field during the handshake.  
    *   Using its corresponding decryption key (derived from its X25519 private key), it attempts to **decrypt and extract the domain ID, port, and ALPN**.
    *   If successful, it retrieves the actual domain name from its local cache.
    *   The server connects to the true destination and relays traffic.
This process hides critical destination information within a standard-looking TLS handshake, making it extremely difficult for network observers to determine the true traffic destination.

## Getting Started
### Building
Requires Go (1.24+). Run:
```
go build -ldflags "-s -w" -o innerfade ./cmd
```

### Configuration
InnerFade uses separate JSON configuration files for the client and server. Example configuration files are provided in the `examples/` directory.

### Generating Keys and CA
InnerFade provides flags to generate necessary assets:
*   **Generate X25519 Key Pair:**
    ```
    ./innerfade -generate-keypair
    ```
    Outputs public (for client config) and private (for server config) keys.
*   **Generate CA Certificate and Key for MITM:**      
    ```
    ./innerfade -generate-ca -ca-cert ca.crt -ca-key ca.key
    ```
    Generates `ca.crt` and `ca.key`. The CA certificate must be trusted by the client machine/browser.

### Running InnerFade
```
./innerfade -c config.json
```

### Domain Cache Management
Use the `-import-domains` and `-export-domains` flags with the respective config files to manage domain lists in the cache.

## Security Considerations
*   **Client-Side MITM:** Client-side MITM means InnerFade can decrypt and inspect all incoming HTTPS traffic. **Installing the generated CA certificate requires full trust in the tool and its operator.**
*   **Key Management:** The security relies on the **confidentiality of the X25519 private key**. Protect it carefully. Protect it carefully.
*   **Trust:** Always verify the source and integrity of the InnerFade executable.