package cache

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"

	"innerfade/common/crypto"

	_ "github.com/mattn/go-sqlite3"
)

const IDLength = 8

type DomainCache struct {
	db        *sql.DB
	stmtGet   *sql.Stmt
	stmtSet   *sql.Stmt
	closeOnce sync.Once
}

func NewDomainCache(dbPath string) (*DomainCache, error) {
	dsn := fmt.Sprintf("%s?cache=shared&mode=rwc", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}

	if _, err := db.Exec("PRAGMA synchronous=NORMAL;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set synchronous mode: %w", err)
	}

	if _, err := db.Exec("PRAGMA busy_timeout=5000;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set busy timeout: %w", err)
	}

	sqlStmt := `
	CREATE TABLE IF NOT EXISTS domains (
		id BLOB PRIMARY KEY,
		domain TEXT NOT NULL
	);
	`
	if _, err := db.Exec(sqlStmt); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	c := &DomainCache{db: db}

	if c.stmtGet, err = db.Prepare("SELECT domain FROM domains WHERE id = ?"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to prepare get stmt: %w", err)
	}
	if c.stmtSet, err = db.Prepare("REPLACE INTO domains (id, domain) VALUES (?, ?)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to prepare set stmt: %w", err)
	}

	return c, nil
}

func (c *DomainCache) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.stmtGet != nil {
			c.stmtGet.Close()
		}
		if c.stmtSet != nil {
			c.stmtSet.Close()
		}
		err = c.db.Close()
	})
	return err
}

func (c *DomainCache) Get(ctx context.Context, id [IDLength]byte) (string, bool, error) {
	var domain string
	err := c.stmtGet.QueryRowContext(ctx, id[:]).Scan(&domain)
	if err == sql.ErrNoRows {
		return "", false, nil
	} else if err != nil {
		return "", false, fmt.Errorf("query error: %w", err)
	}

	return domain, true, nil
}

func (c *DomainCache) Set(ctx context.Context, domain string) ([IDLength]byte, error) {
	id := GenerateID(domain)
	_, err := c.stmtSet.ExecContext(ctx, id[:], domain)
	if err != nil {
		return id, fmt.Errorf("exec error: %w", err)
	}
	return id, nil
}

func GenerateID(domain string) [IDLength]byte {
	hash := sha256.Sum256([]byte(domain))
	var id [IDLength]byte
	copy(id[:], hash[:IDLength])
	return id
}

func EncodeRandom(id [IDLength]byte, port uint16, alpnCode byte, encryptionKey []byte) ([32]byte, error) {
	var random [32]byte

	copy(random[0:8], id[:])
	binary.BigEndian.PutUint16(random[8:10], port)
	random[10] = alpnCode

	hash := sha256.Sum256(random[0:11])
	copy(random[11:19], hash[0:8])

	if _, err := rand.Read(random[19:32]); err != nil {
		return [32]byte{}, fmt.Errorf("random nonce error: %w", err)
	}

	encryptedData, err := crypto.AESEncryptWithNonce(random[0:19], encryptionKey, random[19:32])
	if err != nil {
		return [32]byte{}, fmt.Errorf("encryption error: %w", err)
	}

	copy(random[0:19], encryptedData)

	return random, nil
}

func DecodeRandom(random [32]byte, encryptionKey []byte) (id [IDLength]byte, port uint16, alpnCode byte, ok bool) {
	decryptedData, err := crypto.AESDecryptWithNonce(random[0:19], encryptionKey, random[19:32])
	if err != nil {
		return [IDLength]byte{}, 0, 0, false
	}

	expectedHash := decryptedData[11:19]

	calculatedHashFull := sha256.Sum256(decryptedData[0:11])
	calculatedHashTruncated := calculatedHashFull[0:8]

	if subtle.ConstantTimeCompare(calculatedHashTruncated, expectedHash) != 1 {
		return [IDLength]byte{}, 0, 0, false
	}

	copy(id[:], decryptedData[0:8])
	port = binary.BigEndian.Uint16(decryptedData[8:10])
	alpnCode = decryptedData[10]
	ok = true

	return
}

func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	if len(domain) > 253 {
		return false
	}

	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	regex := regexp.MustCompile(pattern)

	if regex.MatchString(domain) {
		return true
	}

	if net.ParseIP(domain) != nil {
		return true
	}

	return false
}

func (c *DomainCache) ImportDomainsFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	ctx := context.Background()

	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}

		if !IsValidDomain(domain) {
			continue
		}

		if _, err := c.Set(ctx, domain); err != nil {

			_ = err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	return nil
}

func (c *DomainCache) ExportDomainsToFile(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	rows, err := c.db.Query("SELECT domain FROM domains")
	if err != nil {
		return fmt.Errorf("failed to query domains: %w", err)
	}
	defer rows.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return fmt.Errorf("failed to scan domain: %w", err)
		}

		if _, err := writer.WriteString(domain + "\n"); err != nil {
			return fmt.Errorf("failed to write domain to file: %w", err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating rows: %w", err)
	}

	return nil
}
