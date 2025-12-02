package compress

import (
	"testing"
)

func TestCompressDecompress(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"Google", "google.com"},
		{"China Domain", "abc.cn"},
		{"Org Domain", "example.org"},
		{"Numeric IO", "12345.io"},
		{"Hyphens", "a-b-c.net"},
		{"Long Domain", "very-long-domain-name-with-no-common-suffix.uk"},
		{"Subdomain", "www.youtube.com"},
	}

	for _, tt := range tests {
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
				t.Errorf("Round trip failed. Got %q, want %q", decompressed, tt.input)
			}
			if len(compressed) >= len(tt.input) {
				t.Logf("Warning: Compressed size (%d) is not smaller than original (%d)", len(compressed), len(tt.input))
			}
		})
	}
}
