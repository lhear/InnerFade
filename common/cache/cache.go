package cache

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"unsafe"
)

const (
	IDLength        = 8
	IndexSlotSize   = 8
	MinIndexSlots   = 1 << 18
	MaxDataFileSize = 1 << 32
	ProbeBatchSize  = 16
	DataHeaderSize  = IDLength + 1
	LoadFactor      = 0.75
	MaxProbeLoop    = 1000
)

type DomainCache struct {
	mu         sync.RWMutex
	dataFile   *os.File
	indexFile  *os.File
	dataOffset uint32

	indexSlots uint64
	indexMask  uint64
	itemCount  uint64

	dbPath    string
	closeOnce sync.Once
}

func NewDomainCache(dbPath string) (*DomainCache, error) {
	dataPath := dbPath + ".data"
	idxPath := dbPath + ".idx"

	df, err := os.OpenFile(dataPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open data file: %w", err)
	}

	stat, err := df.Stat()
	if err != nil {
		df.Close()
		return nil, err
	}
	currentDataSize := stat.Size()

	if currentDataSize == 0 {
		if _, err := df.Write([]byte{0}); err != nil {
			df.Close()
			return nil, err
		}
		currentDataSize = 1
	}

	if currentDataSize > MaxDataFileSize {
		df.Close()
		return nil, errors.New("data file exceeds 4GB limit")
	}

	idxF, err := os.OpenFile(idxPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		df.Close()
		return nil, fmt.Errorf("failed to open index file: %w", err)
	}

	idxStat, err := idxF.Stat()
	if err != nil {
		df.Close()
		idxF.Close()
		return nil, err
	}

	currentIdxSize := idxStat.Size()
	var slots uint64

	if currentIdxSize == 0 {
		slots = MinIndexSlots
		if err := idxF.Truncate(int64(slots * IndexSlotSize)); err != nil {
			df.Close()
			idxF.Close()
			return nil, fmt.Errorf("failed to init index file: %w", err)
		}
	} else {
		slots = uint64(currentIdxSize) / IndexSlotSize
		if slots < MinIndexSlots {
			slots = MinIndexSlots
			if err := idxF.Truncate(int64(slots * IndexSlotSize)); err != nil {
				df.Close()
				idxF.Close()
				return nil, err
			}
		}
	}

	c := &DomainCache{
		dataFile:   df,
		indexFile:  idxF,
		dataOffset: uint32(currentDataSize),
		indexSlots: slots,
		indexMask:  slots - 1,
		dbPath:     dbPath,
	}

	count, err := c.countItems()
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to scan index items: %w", err)
	}
	c.itemCount = count
	return c, nil
}

func (c *DomainCache) countItems() (uint64, error) {
	var count uint64
	buf := make([]byte, 64*1024)

	if _, err := c.indexFile.Seek(0, 0); err != nil {
		return 0, err
	}

	for {
		n, err := c.indexFile.Read(buf)
		if n > 0 {
			numSlots := n / IndexSlotSize
			for i := 0; i < numSlots; i++ {
				ptr := unsafe.Pointer(&buf[i*IndexSlotSize])
				val := *(*uint64)(ptr)
				if val != 0 {
					count++
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	return count, nil
}

func (c *DomainCache) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err1 := c.indexFile.Close()
		err2 := c.dataFile.Close()
		if err1 != nil {
			err = err1
		} else {
			err = err2
		}
	})
	return err
}

func (c *DomainCache) Get(ctx context.Context, id [IDLength]byte) (string, bool, error) {
	tag := binary.LittleEndian.Uint32(id[:4])
	if tag == 0 {
		tag = 1
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	mask := c.indexMask
	slots := c.indexSlots
	startSlot := uint64(tag) & mask
	currentSlot := startSlot
	var buf [ProbeBatchSize * IndexSlotSize]byte

	for loop := 0; loop < MaxProbeLoop; loop++ {
		readOffset := int64(currentSlot) * IndexSlotSize

		if readOffset >= int64(slots)*IndexSlotSize {
			break
		}
		n, err := c.indexFile.ReadAt(buf[:], readOffset)
		if err != nil && n == 0 {
			return "", false, fmt.Errorf("read index error: %w", err)
		}

		slotsRead := n / IndexSlotSize
		for i := 0; i < slotsRead; i++ {
			ptr := unsafe.Pointer(&buf[i*IndexSlotSize])
			entry := *(*uint64)(ptr)
			if entry == 0 {
				return "", false, nil
			}
			storedTag := uint32(entry)
			storedOffset := uint32(entry >> 32)

			if storedTag == tag {
				domain, match, err := c.verifyAndRead(id, storedOffset)
				if err != nil {
					return "", false, err
				}
				if match {
					return domain, true, nil
				}

			}
		}
		currentSlot = (currentSlot + uint64(slotsRead)) & mask
		if currentSlot == startSlot {
			return "", false, nil
		}
	}
	return "", false, nil
}

func (c *DomainCache) verifyAndRead(expectedID [IDLength]byte, offset uint32) (string, bool, error) {
	header := make([]byte, DataHeaderSize)
	if _, err := c.dataFile.ReadAt(header, int64(offset)); err != nil {
		return "", false, fmt.Errorf("read header: %w", err)
	}
	if string(header[:IDLength]) != string(expectedID[:]) {
		return "", false, nil
	}
	domainLen := int(header[IDLength])
	domainBytes := make([]byte, domainLen)

	if _, err := c.dataFile.ReadAt(domainBytes, int64(offset)+DataHeaderSize); err != nil {
		return "", false, fmt.Errorf("read body: %w", err)
	}
	return string(domainBytes), true, nil
}

func (c *DomainCache) Set(ctx context.Context, domain string) ([IDLength]byte, error) {
	if len(domain) > 255 {
		return [IDLength]byte{}, errors.New("domain too long")
	}
	id := GenerateID(domain)
	_, exists, err := c.Get(ctx, id)
	if err != nil {
		return id, err
	}
	if exists {
		return id, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if float64(c.itemCount) >= float64(c.indexSlots)*LoadFactor {
		if err := c.resizeIndex(); err != nil {
			return id, fmt.Errorf("resize failed: %w", err)
		}
	}

	tag := binary.LittleEndian.Uint32(id[:4])
	if tag == 0 {
		tag = 1
	}

	domainBytes := []byte(domain)
	totalLen := DataHeaderSize + len(domainBytes)

	if uint64(c.dataOffset)+uint64(totalLen) > MaxDataFileSize {
		return id, errors.New("data file full")
	}

	writeOffset := c.dataOffset
	buf := make([]byte, totalLen)
	copy(buf[0:IDLength], id[:])
	buf[IDLength] = byte(len(domainBytes))
	copy(buf[DataHeaderSize:], domainBytes)

	if _, err := c.dataFile.WriteAt(buf, int64(writeOffset)); err != nil {
		return id, fmt.Errorf("write data error: %w", err)
	}
	c.dataOffset += uint32(totalLen)
	startSlot := uint64(tag) & c.indexMask
	currentSlot := startSlot
	var idxBuf [ProbeBatchSize * IndexSlotSize]byte

	for loop := 0; loop < MaxProbeLoop; loop++ {
		readOffset := int64(currentSlot) * IndexSlotSize
		c.indexFile.ReadAt(idxBuf[:], readOffset)

		for i := 0; i < ProbeBatchSize; i++ {
			ptr := unsafe.Pointer(&idxBuf[i*IndexSlotSize])
			entry := *(*uint64)(ptr)
			if entry == 0 {
				newEntry := (uint64(writeOffset) << 32) | uint64(tag)
				var writeBuf [8]byte
				binary.LittleEndian.PutUint64(writeBuf[:], newEntry)
				targetOffset := readOffset + int64(i*IndexSlotSize)
				if _, err := c.indexFile.WriteAt(writeBuf[:], targetOffset); err != nil {
					return id, fmt.Errorf("write index error: %w", err)
				}
				c.itemCount++
				return id, nil
			}
		}
		currentSlot = (currentSlot + ProbeBatchSize) & c.indexMask
		if currentSlot == startSlot {
			return id, errors.New("index file full (unexpected)")
		}
	}
	return id, errors.New("failed to find index slot (too many collisions)")
}

func (c *DomainCache) resizeIndex() error {
	newSlots := c.indexSlots * 2
	newMask := newSlots - 1
	newTotalSize := int(newSlots * IndexSlotSize)
	newIdxBuf := make([]byte, newTotalSize)
	if _, err := c.indexFile.Seek(0, 0); err != nil {
		return err
	}
	readBuf := make([]byte, 256*1024)
	for {
		n, err := c.indexFile.Read(readBuf)
		if n > 0 {
			count := n / IndexSlotSize
			for k := 0; k < count; k++ {
				ptr := unsafe.Pointer(&readBuf[k*IndexSlotSize])
				entry := *(*uint64)(ptr)
				if entry == 0 {
					continue
				}
				tag := uint32(entry)
				startSlot := uint64(tag) & newMask
				currentSlot := startSlot

				inserted := false
				for probe := 0; probe < MaxProbeLoop; probe++ {
					offsetInBuf := int(currentSlot) * IndexSlotSize
					slotPtr := unsafe.Pointer(&newIdxBuf[offsetInBuf])
					val := *(*uint64)(slotPtr)
					if val == 0 {
						*(*uint64)(slotPtr) = entry
						inserted = true
						break
					}
					currentSlot = (currentSlot + 1) & newMask
				}
				if !inserted {
					return errors.New("resize failed: memory buffer crowded")
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	tmpPath := c.dbPath + ".idx.tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if _, err := tmpFile.Write(newIdxBuf); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	oldPath := c.dbPath + ".idx"
	c.indexFile.Close()

	backupPath := c.dbPath + ".idx.bak"
	os.Remove(backupPath)
	os.Rename(oldPath, backupPath)

	if err := os.Rename(tmpPath, oldPath); err != nil {
		os.Rename(backupPath, oldPath)
		return fmt.Errorf("failed to rename new index: %w", err)
	}
	os.Remove(backupPath)

	newF, err := os.OpenFile(oldPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to reopen new index: %w", err)
	}

	c.indexFile = newF
	c.indexSlots = newSlots
	c.indexMask = newMask

	return nil
}

func (c *DomainCache) ImportDomainsFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	ctx := context.Background()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := line
		if idx := strings.IndexAny(line, " \t"); idx > 0 {
			domain = line[:idx]
		}
		if !IsValidDomain(domain) {
			continue
		}
		if _, err := c.Set(ctx, domain); err != nil {

		}
	}
	return scanner.Err()
}

func (c *DomainCache) ExportDomainsToFile(filePath string) error {
	outFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	c.mu.RLock()
	defer c.mu.RUnlock()

	var offset int64 = 1
	fileSize := int64(c.dataOffset)
	header := make([]byte, DataHeaderSize)

	for offset < fileSize {
		if _, err := c.dataFile.ReadAt(header, offset); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("read error at %d: %w", offset, err)
		}

		domainLen := int64(header[IDLength])
		if domainLen == 0 {
			offset += int64(DataHeaderSize)
			continue
		}

		domainBytes := make([]byte, domainLen)
		if _, err := c.dataFile.ReadAt(domainBytes, offset+int64(DataHeaderSize)); err != nil {
			return err
		}

		domain := string(domainBytes)
		if _, err := writer.WriteString(domain + "\n"); err != nil {
			return err
		}

		offset += int64(DataHeaderSize) + domainLen
	}
	return nil
}

func GenerateID(domain string) [IDLength]byte {
	hash := sha256.Sum256([]byte(domain))
	var id [IDLength]byte
	copy(id[:], hash[:IDLength])
	return id
}

func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}
	if len(domain) > 253 {
		return false
	}
	if strings.Contains(domain, "..") {
		return false
	}
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	match, _ := regexp.MatchString(pattern, domain)
	if match {
		return true
	}
	if net.ParseIP(domain) != nil {
		return true
	}
	return false
}
