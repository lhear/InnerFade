package compress

import (
	"fmt"
	"strings"
	"testing"
)

var testCases = []struct {
	name  string
	input string
}{
	{"Short", "google.com"},
	{"Medium", "xaaaaaaaaaaaaaaaaaabc.cn"},
	{"Long", "www.very-long-subdomain-name-for-testing-purposes.youtube.com"},
}

func TestCompressDecompress(t *testing.T) {
	fmt.Printf("%-25s | %-10s | %-10s | %s\n", "Case Name", "Orig(B)", "Comp(B)", "Ratio")
	fmt.Println(strings.Repeat("-", 70))
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := Compress(tt.input)
			if err != nil {
				t.Fatalf("Compress() error = %v", err)
			}
			decompressed, err := Decompress(compressed)
			if err != nil {
				t.Fatalf("Decompress() error = %v", err)
			}
			if decompressed != tt.input {
				t.Errorf("Round trip failed.\nGot:  %q\nWant: %q", decompressed, tt.input)
			}
			origSize := len(tt.input)
			compSize := len(compressed)
			ratio := float64(compSize) / float64(origSize) * 100.0
			t.Logf("Stats: Orig=%d, Comp=%d, Ratio=%.2f%%", origSize, compSize, ratio)
			fmt.Printf("%-25s | %-10d | %-10d | %.2f%%\n", tt.name, origSize, compSize, ratio)
		})
	}
}

func BenchmarkCompress(b *testing.B) {
	for _, tt := range testCases {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = Compress(tt.input)
			}
		})
	}
}

func BenchmarkDecompress(b *testing.B) {
	for _, tt := range testCases {
		compressed, err := Compress(tt.input)
		if err != nil {
			b.Fatalf("Setup failed: %v", err)
		}
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = Decompress(compressed)
			}
		})
	}
}
