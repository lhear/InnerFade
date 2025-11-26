package cache

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPerformance_DynamicResize(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "perf_test_db")

	cache, err := NewDomainCache(dbPath)
	if err != nil {
		t.Fatalf("Failed to init cache: %v", err)
	}
	defer cache.Close()

	const totalItems = 500_000
	ctx := context.Background()

	t.Logf("Starting write test with %d items...", totalItems)

	var maxLatency time.Duration
	var totalDuration time.Duration
	slowestIndex := 0

	startTotal := time.Now()

	for i := 0; i < totalItems; i++ {
		domain := fmt.Sprintf("u-%d-perf-test.com", i)
		start := time.Now()
		_, err := cache.Set(ctx, domain)
		cost := time.Since(start)
		if err != nil {
			t.Fatalf("Set failed at index %d: %v", i, err)
		}
		if cost > maxLatency {
			maxLatency = cost
			slowestIndex = i
		}
		totalDuration += cost
	}

	elapsed := time.Since(startTotal)
	avgLatency := totalDuration / time.Duration(totalItems)
	ops := float64(totalItems) / elapsed.Seconds()

	t.Logf("------------------------------------------------")
	t.Logf("Write Performance Summary:")
	t.Logf("Total Items:   %d", totalItems)
	t.Logf("Total Time:    %v", elapsed)
	t.Logf("Throughput:    %.2f OPS", ops)
	t.Logf("Avg Latency:   %v", avgLatency)
	t.Logf("Max Latency:   %v (happened at item #%d)", maxLatency, slowestIndex)
	t.Logf("------------------------------------------------")

	if maxLatency > 1*time.Second {
		t.Errorf("WARNING: Resize latency is too high: %v. Optimization might be needed.", maxLatency)
	} else {
		t.Logf("SUCCESS: Resize latency is controlled: %v", maxLatency)
	}

	t.Run("ReadPerformance", func(t *testing.T) {
		start := time.Now()
		checkCount := 10000
		foundCount := 0
		for i := 0; i < checkCount; i++ {
			targetIdx := rand.Intn(totalItems)
			domain := fmt.Sprintf("u-%d-perf-test.com", targetIdx)
			id := GenerateID(domain)
			val, found, err := cache.Get(ctx, id)
			if err != nil {
				t.Fatalf("Read error: %v", err)
			}
			if found && val == domain {
				foundCount++
			}
		}
		t.Logf("Read %d random items took %v. Found: %d/%d", checkCount, time.Since(start), foundCount, checkCount)
	})
}

func TestConcurrency_Safety(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "concurrent_test_db")

	c, err := NewDomainCache(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	ctx := context.Background()
	concurrency := 50
	itemsPerRoutine := 1000

	t.Logf("Starting concurrency test: %d goroutines, %d writes each", concurrency, itemsPerRoutine)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			for j := 0; j < itemsPerRoutine; j++ {
				domain := fmt.Sprintf("g-%d-item-%d.com", routineID, j)
				if _, err := c.Set(ctx, domain); err != nil {
					t.Errorf("Concurrent set failed: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	c.mu.RLock()
	count := c.itemCount
	c.mu.RUnlock()

	expected := uint64(concurrency * itemsPerRoutine)
	if count != expected {
		t.Errorf("Item count mismatch. Expected %d, got %d", expected, count)
	}
	t.Log("Concurrency test passed.")
}

func TestPersistence_Reload(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "persist_db")
	ctx := context.Background()
	{
		c, _ := NewDomainCache(dbPath)
		for i := 0; i < 50000; i++ {
			c.Set(ctx, fmt.Sprintf("p-%d.com", i))
		}
		c.Close()
	}
	start := time.Now()
	c2, err := NewDomainCache(dbPath)
	if err != nil {
		t.Fatalf("Failed to reload cache: %v", err)
	}
	loadTime := time.Since(start)
	defer c2.Close()

	t.Logf("Reloaded 50k items in %v", loadTime)

	id := GenerateID("p-12345.com")
	val, found, err := c2.Get(ctx, id)
	if err != nil || !found || val != "p-12345.com" {
		t.Fatalf("Failed to retrieve data after reload. Found: %v, Val: %s", found, val)
	}

	c2.mu.RLock()
	restoredCount := c2.itemCount
	c2.mu.RUnlock()

	if restoredCount < 50000 {
		t.Errorf("Lost data? Restored count: %d", restoredCount)
	}
}

func BenchmarkWrite(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench_write")
	c, _ := NewDomainCache(dbPath)
	defer c.Close()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		domain := fmt.Sprintf("bench-%d.com", i)
		c.Set(ctx, domain)
	}
}

func BenchmarkRead(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench_read")
	c, _ := NewDomainCache(dbPath)
	defer c.Close()
	ctx := context.Background()

	items := 100000
	ids := make([][8]byte, items)
	for i := 0; i < items; i++ {
		d := fmt.Sprintf("bench-%d.com", i)
		id, _ := c.Set(ctx, d)
		ids[i] = id
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % items
		c.Get(ctx, ids[idx])
	}
}
