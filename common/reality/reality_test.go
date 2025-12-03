package reality

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestRealityConnection(t *testing.T) {
	t.Log("Starting REALITY client-server connection test...")

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := privateKey.PublicKey()

	var clientMetaData [48]byte
	var serverMetaData [12]byte

	rand.Read(clientMetaData[:])
	rand.Read(serverMetaData[:])

	clientMetaDataReceivedChan := make(chan []byte, 1)

	serverConfig := &Config{
		PrivateKey:  privateKey.Bytes(),
		ServerNames: []string{"www.apple.com"},
		Show:        true,
		Dest:        "www.apple.com:443",
		Type:        "tcp",
		MaxTimeDiff: 60 * 1000,
	}

	serverConfig.GetServerMetaDataForClient = func(remoteAddr string, data []byte) []byte {
		if !EqualBytes(data, clientMetaData[:]) {
			t.Errorf("Server received unexpected client MetaData. Expected: %v, Got: %v", clientMetaData, data)
		} else {
			select {
			case clientMetaDataReceivedChan <- data:
			default:
			}
		}
		return serverMetaData[:]
	}

	fingerprint, err := ParseFingerprintStr("chrome")
	if err != nil {
		t.Fatalf("%v", err)
	}

	clientConfig := &Config{
		ServerName:     "www.apple.com",
		PublicKey:      publicKey.Bytes(),
		Fingerprint:    fingerprint,
		Show:           true,
		ClientMetaData: clientMetaData,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:12345")
	if err != nil {
		t.Fatalf("Failed to start REALITY server listener: %v", err)
	}
	defer listener.Close()

	t.Logf("REALITY server listening on %s", listener.Addr().String())

	var serverWg sync.WaitGroup
	done := make(chan struct{})

	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					t.Logf("Server Accept error: %v", err)
					return
				}
			}

			serverWg.Add(1)
			go func(conn net.Conn) {
				defer serverWg.Done()
				defer conn.Close()

				rConn, err := Server(conn, serverConfig)
				if err != nil {
					t.Errorf("REALITY server handshake failed: %v", err)
					return
				}

				buf := make([]byte, 1024)
				_, err = rConn.Read(buf)
				if err != nil && err != io.EOF {
					t.Errorf("Server Read error: %v", err)
					return
				}

				response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello")
				if _, err := rConn.Write(response); err != nil {
					t.Errorf("Server Write error: %v", err)
					return
				}
			}(conn)
		}
	}()

	t.Run("ClientTest", func(t *testing.T) {
		time.Sleep(100 * time.Millisecond)

		clientConn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("Failed to connect to REALITY server: %v", err)
		}
		defer clientConn.Close()

		t.Log("Connecting client to REALITY server...")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		realityClientConn, err := UClient(clientConn, clientConfig, ctx, "localhost")
		if err != nil {
			t.Fatalf("REALITY client connection failed: %v", err)
		}

		if rConn, ok := realityClientConn.(*UConn); ok {
			if !EqualBytes(rConn.ServerMetaData[:], serverMetaData[:]) {
				t.Errorf("Client received unexpected server MetaData. Expected: %v, Got: %v", serverMetaData, rConn.ServerMetaData[:])
			} else {
				t.Log("Client successfully verified server MetaData.")
			}
		} else {
			t.Error("Cannot verify server MetaData because reality.UClient returned type cannot be asserted.")
		}

		select {
		case received := <-clientMetaDataReceivedChan:
			if EqualBytes(received, clientMetaData[:]) {
				t.Log("Server successfully received and verified client MetaData.")
			} else {
				t.Errorf("Server received unexpected client MetaData in GetServerMetaDataForClient. Expected: %v, Got: %v", clientMetaData, received)
			}
		case <-time.After(500 * time.Millisecond):
			t.Error("Timeout waiting for server to receive and process client MetaData.")
		}

		message := "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Reality-Test/1.0\r\n\r\n"
		if _, wErr := realityClientConn.Write([]byte(message)); wErr != nil {
			t.Errorf("Error writing to client connection: %v", wErr)
			return
		}

		buffer := make([]byte, 1024)
		n, rErr := realityClientConn.Read(buffer)
		if rErr != nil {
			t.Errorf("Error reading from client connection: %v", rErr)
			return
		}

		receivedResponse := string(buffer[:n])
		expectedResponse := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"
		if receivedResponse != expectedResponse {
			t.Errorf("Received unexpected response. Expected: %q, Got: %q", expectedResponse, receivedResponse)
		}

		if cErr := realityClientConn.Close(); cErr != nil {
			t.Errorf("Error closing reality client connection: %v", cErr)
		}
	})

	close(done)
	listener.Close()
	serverWg.Wait()

	t.Log("REALITY client-server connection test completed successfully")
}

func EqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
