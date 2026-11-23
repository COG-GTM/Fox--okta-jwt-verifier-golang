package jwtverifier

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/okta/okta-jwt-verifier-golang/adaptors"
	"github.com/okta/okta-jwt-verifier-golang/discovery"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const testKid = "test-kid"

type testIssuer struct {
	server       *httptest.Server
	key          *rsa.PrivateKey
	metadataHits int32
	jwksHits     int32
	omitJwksUri  bool
	metadataBody string
}

func newTestIssuer(t *testing.T) *testIssuer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate rsa key: %s", err)
	}

	ti := &testIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&ti.metadataHits, 1)
		w.Header().Set("Content-Type", "application/json")
		if ti.metadataBody != "" {
			fmt.Fprint(w, ti.metadataBody)
			return
		}
		md := map[string]interface{}{"issuer": ti.server.URL}
		if !ti.omitJwksUri {
			md["jwks_uri"] = ti.server.URL + "/keys"
		}
		json.NewEncoder(w).Encode(md)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&ti.jwksHits, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, jwksJson(&key.PublicKey))
	})
	ti.server = httptest.NewServer(mux)
	return ti
}

func (ti *testIssuer) Close() { ti.server.Close() }

func (ti *testIssuer) URL() string { return ti.server.URL }

func jwksJson(pub *rsa.PublicKey) string {
	enc := base64.RawURLEncoding
	keys := map[string]interface{}{
		"keys": []map[string]string{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": testKid,
			"n":   enc.EncodeToString(pub.N.Bytes()),
			"e":   enc.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
	b, _ := json.Marshal(keys)
	return string(b)
}

func signToken(t *testing.T, key *rsa.PrivateKey, header map[string]interface{}, claims map[string]interface{}) string {
	enc := base64.RawURLEncoding
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("could not marshal header: %s", err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("could not marshal claims: %s", err)
	}
	signingInput := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("could not sign token: %s", err)
	}
	return signingInput + "." + enc.EncodeToString(sig)
}

func (ti *testIssuer) token(t *testing.T, claims map[string]interface{}) string {
	return signToken(t, ti.key, map[string]interface{}{"alg": "RS256", "kid": testKid}, claims)
}

func (ti *testIssuer) accessClaims() map[string]interface{} {
	now := time.Now().Unix()
	return map[string]interface{}{
		"iss": ti.URL(),
		"aud": "api://default",
		"cid": "client-id",
		"exp": now + 3600,
		"iat": now,
	}
}

func (ti *testIssuer) idClaims() map[string]interface{} {
	now := time.Now().Unix()
	return map[string]interface{}{
		"iss":   ti.URL(),
		"aud":   "client-id",
		"exp":   now + 3600,
		"iat":   now,
		"nonce": "nonce-value",
	}
}

func encodeHeader(t *testing.T, header interface{}) string {
	b, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("could not marshal header: %s", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type fakeAdaptor struct {
	claims interface{}
	err    error
	jwkUri string
}

func (f *fakeAdaptor) New() adaptors.Adaptor { return f }

func (f *fakeAdaptor) GetKey(jwkUri string) {}

func (f *fakeAdaptor) Decode(jwt string, jwkUri string) (interface{}, error) {
	f.jwkUri = jwkUri
	return f.claims, f.err
}

type fakeDiscovery struct {
	url string
}

func (f fakeDiscovery) New() discovery.Discovery { return f }

func (f fakeDiscovery) GetWellKnownUrl() string { return f.url }
