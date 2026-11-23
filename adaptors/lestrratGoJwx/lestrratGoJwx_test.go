package lestrratGoJwx

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type jwksServer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	hits   int32
}

func newJwksServer(t *testing.T) *jwksServer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate rsa key: %s", err)
	}
	js := &jwksServer{key: key}
	js.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&js.hits, 1)
		enc := base64.RawURLEncoding
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"k1","n":%q,"e":%q}]}`,
			enc.EncodeToString(key.PublicKey.N.Bytes()),
			enc.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()))
	}))
	return js
}

func (js *jwksServer) sign(t *testing.T, claims map[string]interface{}) string {
	enc := base64.RawURLEncoding
	c, _ := json.Marshal(claims)
	input := enc.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`)) + "." + enc.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, js.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("could not sign: %s", err)
	}
	return input + "." + enc.EncodeToString(sig)
}

func Test_new_returns_adaptor(t *testing.T) {
	adaptor := LestrratGoJwx{}.New()
	if _, ok := adaptor.(LestrratGoJwx); !ok {
		t.Errorf("expected LestrratGoJwx, got %T", adaptor)
	}
	adaptor.GetKey("https://example.com/keys")
}

func Test_decode_returns_claims_for_valid_signature(t *testing.T) {
	js := newJwksServer(t)
	defer js.server.Close()

	claims, err := LestrratGoJwx{}.Decode(js.sign(t, map[string]interface{}{"sub": "user", "exp": 123}), js.server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	m, ok := claims.(map[string]interface{})
	if !ok {
		t.Fatalf("expected claims map, got %T", claims)
	}
	if m["sub"] != "user" || m["exp"] != float64(123) {
		t.Errorf("unexpected claims: %v", m)
	}
}

func Test_decode_rejects_signature_from_other_key(t *testing.T) {
	js := newJwksServer(t)
	defer js.server.Close()
	other := newJwksServer(t)
	defer other.server.Close()

	_, err := LestrratGoJwx{}.Decode(other.sign(t, map[string]interface{}{"sub": "user"}), js.server.URL)
	if err == nil || !strings.Contains(err.Error(), "failed to verify with any of the keys") {
		t.Errorf("expected verification failure, got %v", err)
	}
}

func Test_decode_rejects_malformed_token(t *testing.T) {
	js := newJwksServer(t)
	defer js.server.Close()

	if _, err := (LestrratGoJwx{}).Decode("not-a-jwt", js.server.URL); err == nil {
		t.Errorf("expected malformed token to fail")
	}
}

func Test_decode_returns_error_when_jwks_unreachable(t *testing.T) {
	js := newJwksServer(t)
	url := js.server.URL
	js.server.Close()

	if _, err := (LestrratGoJwx{}).Decode("a.b.c", url); err == nil {
		t.Errorf("expected error when jwks endpoint is unreachable")
	}
}

func Test_get_jwk_set_caches_by_uri(t *testing.T) {
	js := newJwksServer(t)
	defer js.server.Close()

	first, err := getJwkSet(js.server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	second, err := getJwkSet(js.server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if first != second {
		t.Errorf("expected cached jwk set to be reused")
	}
	if hits := atomic.LoadInt32(&js.hits); hits != 1 {
		t.Errorf("expected one jwks fetch, got %d", hits)
	}
	if len(first.Keys) != 1 {
		t.Errorf("expected one key, got %d", len(first.Keys))
	}
}

func Test_get_jwk_set_does_not_cache_failures(t *testing.T) {
	js := newJwksServer(t)
	url := js.server.URL
	js.server.Close()

	if _, err := getJwkSet(url); err == nil {
		t.Fatalf("expected error for unreachable jwks")
	}
	if _, found := jwkSetCache.Get(url); found {
		t.Errorf("failed fetch should not be cached")
	}
}
