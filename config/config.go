package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"innerfade/common/reality"
	"net"
	"os"
)

type Config struct {
	Mode        string   `json:"mode"`
	ListenAddr  string   `json:"listen_addr"`
	ServerAddr  string   `json:"server_addr"`
	CACert      string   `json:"ca_cert"`
	CAKey       string   `json:"ca_key"`
	CachePath   string   `json:"cache_path"`
	PublicKey   string   `json:"public_key"`
	PrivateKey  string   `json:"private_key"`
	Dest        string   `json:"dest"`
	ServerNames []string `json:"server_names"`
	ServerName  string   `json:"server_name"`
	Socks5Proxy string   `json:"socks5_proxy"`
	LogLevel    string   `json:"log_level,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

func LoadFromJSON(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func (c *Config) Validate() error {
	if c.Mode != "client" && c.Mode != "server" {
		return fmt.Errorf("invalid mode: %s, only supports 'client' or 'server'", c.Mode)
	}

	if c.ListenAddr == "" {
		return fmt.Errorf("listen address cannot be empty")
	}

	if c.CachePath == "" {
		return fmt.Errorf("domain cache file path cannot be empty")
	}

	if c.PublicKey != "" {
		key, err := base64.RawURLEncoding.DecodeString(c.PublicKey)
		if err != nil || len(key) != 32 {
			return fmt.Errorf("invalid public key format")
		}
	}
	if c.PrivateKey != "" {
		key, err := base64.RawURLEncoding.DecodeString(c.PrivateKey)
		if err != nil || len(key) != 32 {
			return fmt.Errorf("invalid private key format")
		}
	}

	switch c.Mode {
	case "client":
		if c.ServerAddr == "" {
			return fmt.Errorf("server address cannot be empty in client mode")
		}
		if c.CACert != "" && c.CAKey == "" {
			return fmt.Errorf("CA certificate provided but CA private key not provided")
		}
		if c.CAKey != "" && c.CACert == "" {
			return fmt.Errorf("CA private key provided but CA certificate not provided")
		}
		if c.PublicKey == "" {
			return fmt.Errorf("PublicKey cannot be empty in client mode")
		}
		if c.ServerName == "" {
			return fmt.Errorf("ServerName cannot be empty in client mode")
		}
		if _, err := reality.ParseFingerprintStr(c.Fingerprint); err != nil {
			return err
		}
	case "server":
		if c.PrivateKey == "" {
			return fmt.Errorf("PrivateKey cannot be empty in server mode")
		}
		if c.Dest == "" {
			return fmt.Errorf("dest cannot be empty in server mode")
		}
		if len(c.ServerNames) == 0 {
			return fmt.Errorf("ServerNames cannot be empty in server mode")
		}

		if c.Socks5Proxy != "" {
			host, port, err := net.SplitHostPort(c.Socks5Proxy)
			if err != nil || host == "" || port == "" {
				return fmt.Errorf("invalid SOCKS5 proxy address format, should be host:port format")
			}
		}
	}

	return nil
}
