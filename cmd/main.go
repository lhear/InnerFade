package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"strings"

	"innerfade/client"
	"innerfade/common"
	"innerfade/common/cache"
	"innerfade/config"
	"innerfade/logger"
	"innerfade/server"
)

var (
	Version = "unknown"
)

var (
	configFile      = flag.String("c", "", "Path to the JSON configuration file.")
	generateKeypair = flag.Bool("generate-keypair", false, "Generate an X25519 private/public key pair.")
	generateCA      = flag.Bool("generate-ca", false, "Generate a new CA certificate and private key.")
	caCertPath      = flag.String("ca-cert", "", "Path to save the generated CA certificate (required when using -generate-ca).")
	caKeyPath       = flag.String("ca-key", "", "Path to save the generated CA private key (required when using -generate-ca).")
	importDomains   = flag.String("import-domains", "", "Import domain list from file to the cache specified in config.")
	exportDomains   = flag.String("export-domains", "", "Export domain list from the cache specified in config to file.")
	version         = flag.Bool("version", false, "Show version information.")
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Version: %s\n", Version)
		return
	}

	if *generateKeypair {
		privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			fmt.Printf("Failed to generate private key: %v", err)
			return
		}
		publicKey := privateKey.PublicKey()
		fmt.Println("Private Key:", base64.RawURLEncoding.EncodeToString(privateKey.Bytes()))
		fmt.Println("Public Key:", base64.RawURLEncoding.EncodeToString(publicKey.Bytes()))
		return
	}

	if *generateCA {
		if *caCertPath == "" || *caKeyPath == "" {
			fmt.Println("When using -generate-ca, you must specify both -ca-cert and -ca-key paths.")
			return
		}

		fmt.Println("Generating new CA certificate and private key...")
		ca, err := common.GenerateTempCA()
		if err != nil {
			fmt.Printf("Failed to generate CA: %v", err)
			return
		}

		if err := ca.SaveToFile(*caCertPath, *caKeyPath); err != nil {
			fmt.Printf("Failed to save CA certificate and key: %v", err)
			return
		}

		fmt.Println("CA certificate and private key generated successfully!")
		return
	}

	if *importDomains != "" || *exportDomains != "" {
		if *configFile == "" {
			fmt.Println("Import/export operation requires a configuration file path via the -c flag to get cache_path.")
			return
		}

		cfg, err := config.LoadFromJSON(*configFile)
		if err != nil {
			fmt.Printf("Failed to load config file: %v", err)
			return
		}
		cachePath := cfg.CachePath

		if cachePath == "" {
			fmt.Println("Domain cache operations require 'cache_path' to be specified in the configuration file.")
			return
		}

		domainCache, err := cache.NewDomainCache(cachePath)
		if err != nil {
			fmt.Printf("Failed to create domain cache: %v", err)
			return
		}
		defer domainCache.Close()

		if *importDomains != "" {
			fmt.Printf("Importing domains from %s to cache...", *importDomains)
			if err := domainCache.ImportDomainsFromFile(*importDomains); err != nil {
				fmt.Printf("Failed to import domains: %v", err)
				return
			}
			fmt.Println("Domain import complete.")
		}

		if *exportDomains != "" {
			fmt.Printf("Exporting domains from cache to %s...", *exportDomains)
			if err := domainCache.ExportDomainsToFile(*exportDomains); err != nil {
				fmt.Printf("Failed to export domains: %v", err)
				return
			}
			fmt.Printf("Domain export complete.")
		}

		return
	}

	if *configFile != "" {
		cfg, err := config.LoadFromJSON(*configFile)
		if err != nil {
			fmt.Printf("Failed to load configuration file: %v", err)
			return
		}

		if err := cfg.Validate(); err != nil {
			fmt.Printf("Configuration validation failed: %v", err)
			return
		}

		if cfg.LogLevel != "" {
			if err := logger.SetLevelFromString(cfg.LogLevel); err != nil {
				fmt.Println(err)
				return
			}
		} else {
			logger.SetLevel(logger.INFO)
		}

		switch strings.ToLower(cfg.Mode) {
		case "client":
			if err := client.Start(cfg); err != nil {
				logger.Fatalf("client failed to start: %v", err)
			}
		case "server":
			if err := server.Start(cfg); err != nil {
				logger.Fatalf("server failed to start: %v", err)
			}
		}
		return
	}

	flag.Usage()
}
