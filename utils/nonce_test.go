package utils

import (
	"encoding/base64"
	"testing"
)

func Test_generate_nonce_is_url_safe_base64_of_32_bytes(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	decoded, err := base64.URLEncoding.DecodeString(nonce)
	if err != nil {
		t.Fatalf("nonce is not url-safe base64: %s", err)
	}
	if len(decoded) != 32 {
		t.Errorf("expected 32 random bytes, got %d", len(decoded))
	}
}

func Test_generate_nonce_is_unique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		nonce, err := GenerateNonce()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if seen[nonce] {
			t.Fatalf("duplicate nonce generated: %s", nonce)
		}
		seen[nonce] = true
	}
}
