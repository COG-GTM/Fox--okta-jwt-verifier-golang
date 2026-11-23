package jwtverifier

import (
	"encoding/base64"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/okta/okta-jwt-verifier-golang/discovery/oidc"
	jwterrors "github.com/okta/okta-jwt-verifier-golang/errors"
)

func newVerifier(issuer string, claims map[string]string) *JwtVerifier {
	jv := JwtVerifier{Issuer: issuer, ClaimsToValidate: claims}
	return jv.New()
}

func accessClaimsToValidate() map[string]string {
	return map[string]string{"aud": "api://default", "cid": "client-id"}
}

func idClaimsToValidate() map[string]string {
	return map[string]string{"aud": "client-id", "nonce": "nonce-value"}
}

func Test_new_sets_default_leeway(t *testing.T) {
	jv := newVerifier("issuer", nil)
	if jv.leeway != 120 {
		t.Errorf("expected default leeway of 120, got %d", jv.leeway)
	}
}

func Test_new_keeps_provided_discovery_and_adaptor(t *testing.T) {
	disc := fakeDiscovery{url: "/custom"}
	adaptor := &fakeAdaptor{}
	jvs := JwtVerifier{Issuer: "issuer", Discovery: disc, Adaptor: adaptor}
	jv := jvs.New()

	if jv.GetDiscovery() != disc {
		t.Errorf("custom discovery was replaced")
	}
	if jv.GetAdaptor() != adaptor {
		t.Errorf("custom adaptor was replaced")
	}
}

func Test_new_default_discovery_uses_openid_configuration(t *testing.T) {
	jv := newVerifier("issuer", nil)
	if got := jv.GetDiscovery().GetWellKnownUrl(); got != "/.well-known/openid-configuration" {
		t.Errorf("unexpected well-known url: %s", got)
	}
}

func Test_set_leeway_changes_exp_and_iat_tolerance(t *testing.T) {
	jv := newVerifier("issuer", nil)
	jv.SetLeeway(0)
	if jv.leeway != 0 {
		t.Fatalf("expected leeway 0, got %d", jv.leeway)
	}

	past := float64(time.Now().Unix() - 60)
	if err := jv.validateExp(past); err == nil {
		t.Errorf("expected token expired 60s ago to fail with zero leeway")
	}
	future := float64(time.Now().Unix() + 60)
	if err := jv.validateIat(future); err == nil {
		t.Errorf("expected token issued 60s in the future to fail with zero leeway")
	}

	jv.SetLeeway(300)
	if err := jv.validateExp(past); err != nil {
		t.Errorf("expected token expired 60s ago to pass with 300s leeway: %s", err)
	}
	if err := jv.validateIat(future); err != nil {
		t.Errorf("expected token issued 60s in the future to pass with 300s leeway: %s", err)
	}
}

func Test_validate_exp_boundaries(t *testing.T) {
	jv := newVerifier("issuer", nil)
	now := time.Now().Unix()

	if err := jv.validateExp(float64(now + 3600)); err != nil {
		t.Errorf("unexpired token failed: %s", err)
	}
	if err := jv.validateExp(float64(now - 60)); err != nil {
		t.Errorf("token expired within leeway failed: %s", err)
	}
	err := jv.validateExp(float64(now - 600))
	if err == nil || err.Error() != "the token is expired" {
		t.Errorf("expected expiry error, got %v", err)
	}
}

func Test_validate_iat_error_message(t *testing.T) {
	jv := newVerifier("issuer", nil)
	err := jv.validateIat(float64(time.Now().Unix() + 600))
	if err == nil || err.Error() != "the token was issued in the future" {
		t.Errorf("expected issued-in-future error, got %v", err)
	}
}

func Test_validate_iss(t *testing.T) {
	jv := newVerifier("https://issuer.example.com", nil)

	if err := jv.validateIss("https://issuer.example.com"); err != nil {
		t.Errorf("matching issuer failed: %s", err)
	}
	err := jv.validateIss("https://other.example.com")
	if err == nil || !strings.Contains(err.Error(), "does not match https://issuer.example.com") {
		t.Errorf("expected issuer mismatch error, got %v", err)
	}
	if err := jv.validateIss(nil); err == nil {
		t.Errorf("missing issuer should fail")
	}
}

func Test_validate_audience(t *testing.T) {
	jv := newVerifier("issuer", map[string]string{"aud": "api://default"})

	if err := jv.validateAudience("api://default"); err != nil {
		t.Errorf("matching audience failed: %s", err)
	}
	if err := jv.validateAudience("api://other"); err == nil {
		t.Errorf("mismatched audience should fail")
	}
	if err := jv.validateAudience(nil); err == nil {
		t.Errorf("missing audience should fail")
	}
}

func Test_validate_client_id(t *testing.T) {
	jv := newVerifier("issuer", map[string]string{"cid": "client-id"})

	if err := jv.validateClientId("client-id"); err != nil {
		t.Errorf("matching client id failed: %s", err)
	}
	err := jv.validateClientId("other")
	if err == nil || !strings.Contains(err.Error(), "clientId: other does not match client-id") {
		t.Errorf("expected client id mismatch error, got %v", err)
	}
}

func Test_validate_nonce(t *testing.T) {
	jv := newVerifier("issuer", map[string]string{"nonce": "abc"})
	if err := jv.validateNonce("abc"); err != nil {
		t.Errorf("matching nonce failed: %s", err)
	}
	if err := jv.validateNonce("xyz"); err == nil {
		t.Errorf("mismatched nonce should fail")
	}
	if err := jv.validateNonce(nil); err == nil {
		t.Errorf("missing nonce should fail when one is expected")
	}
}

func Test_validate_nonce_is_skipped_when_not_configured(t *testing.T) {
	jv := newVerifier("issuer", map[string]string{"aud": "client-id"})
	if err := jv.validateNonce("anything"); err != nil {
		t.Errorf("nonce should not be validated when not in ClaimsToValidate: %s", err)
	}
	if err := jv.validateNonce(nil); err != nil {
		t.Errorf("nonce should not be validated when not in ClaimsToValidate: %s", err)
	}
}

func Test_pad_header(t *testing.T) {
	cases := map[string]string{
		"":      "",
		"abcd":  "abcd",
		"abc":   "abc=",
		"ab":    "ab==",
		"abcde": "abcde===",
	}
	for in, want := range cases {
		if got := padHeader(in); got != want {
			t.Errorf("padHeader(%q) = %q, want %q", in, got, want)
		}
	}
}

func Test_is_valid_jwt(t *testing.T) {
	validHeader := encodeHeader(t, map[string]string{"alg": "RS256", "kid": "abc"})

	cases := []struct {
		name    string
		jwt     string
		wantErr string
	}{
		{"valid", validHeader + ".payload.signature", ""},
		{"no period", "abcdef", "token must contain at least 1 period"},
		{"invalid characters", validHeader + ".payload.sig!", "token must contain at least 1 period"},
		{"header not base64", "a.payload.signature", "does not appear to be a base64 encoded string"},
		{"header not json", base64.RawURLEncoding.EncodeToString([]byte("notjson")) + ".payload.signature", "is not a json object"},
		{"too few properties", encodeHeader(t, map[string]string{"alg": "RS256"}) + ".payload.signature", "does not contain enough properties"},
		{"too many properties", encodeHeader(t, map[string]string{"alg": "RS256", "kid": "abc", "typ": "JWT"}) + ".payload.signature", "contains too many properties"},
		{"missing alg", encodeHeader(t, map[string]string{"foo": "RS256", "kid": "abc"}) + ".payload.signature", "must contain an 'alg'"},
		{"missing kid", encodeHeader(t, map[string]string{"alg": "RS256", "foo": "abc"}) + ".payload.signature", "must contain a 'kid'"},
		{"unsupported alg", encodeHeader(t, map[string]string{"alg": "HS256", "kid": "abc"}) + ".payload.signature", "the only supported alg is RS256"},
	}

	jv := newVerifier("issuer", nil)
	for _, c := range cases {
		ok, err := jv.isValidJwt(c.jwt)
		if c.wantErr == "" {
			if !ok || err != nil {
				t.Errorf("%s: expected valid jwt, got %v", c.name, err)
			}
			continue
		}
		if ok || err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: expected error containing %q, got ok=%v err=%v", c.name, c.wantErr, ok, err)
		}
	}
}

func Test_is_valid_jwt_empty_string_returns_typed_error(t *testing.T) {
	jv := newVerifier("issuer", nil)
	ok, err := jv.isValidJwt("")
	if ok {
		t.Fatalf("empty jwt should not be valid")
	}
	if _, isTyped := err.(*jwterrors.JwtEmptyString); !isTyped {
		t.Errorf("expected *errors.JwtEmptyString, got %T", err)
	}
}

func Test_verify_rejects_empty_and_malformed_tokens(t *testing.T) {
	jv := newVerifier("issuer", nil)

	for _, verify := range []func(string) (*Jwt, error){jv.VerifyAccessToken, jv.VerifyIdToken} {
		claims, err := verify("")
		if claims != nil || err == nil || err.Error() != "token is not valid: you must provide a jwt to verify" {
			t.Errorf("unexpected result for empty token: %v %v", claims, err)
		}
		claims, err = verify("abc")
		if claims != nil || err == nil || !strings.HasPrefix(err.Error(), "token is not valid:") {
			t.Errorf("unexpected result for malformed token: %v %v", claims, err)
		}
	}
}

func Test_verify_access_token_end_to_end(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()

	jv := newVerifier(ti.URL(), accessClaimsToValidate())
	token, err := jv.VerifyAccessToken(ti.token(t, ti.accessClaims()))
	if err != nil {
		t.Fatalf("could not verify access token: %s", err)
	}
	if token.Claims["iss"] != ti.URL() || token.Claims["cid"] != "client-id" {
		t.Errorf("unexpected claims: %v", token.Claims)
	}
}

func Test_verify_id_token_end_to_end(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()

	jv := newVerifier(ti.URL(), idClaimsToValidate())
	token, err := jv.VerifyIdToken(ti.token(t, ti.idClaims()))
	if err != nil {
		t.Fatalf("could not verify id token: %s", err)
	}
	if token.Claims["nonce"] != "nonce-value" {
		t.Errorf("unexpected claims: %v", token.Claims)
	}
}

func Test_verify_access_token_claim_failures(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()
	now := time.Now().Unix()

	cases := []struct {
		claim   string
		value   interface{}
		wantErr string
	}{
		{"iss", "https://evil.example.com", "the `Issuer` was not able to be validated"},
		{"aud", "api://other", "the `Audience` was not able to be validated"},
		{"cid", "other-client", "the `Client Id` was not able to be validated"},
		{"exp", now - 3600, "the `Expiration` was not able to be validated"},
		{"iat", now + 3600, "the `Issued At` was not able to be validated"},
	}

	jv := newVerifier(ti.URL(), accessClaimsToValidate())
	for _, c := range cases {
		claims := ti.accessClaims()
		claims[c.claim] = c.value
		token, err := jv.VerifyAccessToken(ti.token(t, claims))
		if err == nil || !strings.HasPrefix(err.Error(), c.wantErr) {
			t.Errorf("%s: expected error %q, got %v", c.claim, c.wantErr, err)
		}
		if token == nil || token.Claims == nil {
			t.Errorf("%s: expected decoded claims to be returned alongside the error", c.claim)
		}
	}
}

func Test_verify_id_token_claim_failures(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()
	now := time.Now().Unix()

	cases := []struct {
		claim   string
		value   interface{}
		wantErr string
	}{
		{"iss", "https://evil.example.com", "the `Issuer` was not able to be validated"},
		{"aud", "other-client", "the `Audience` was not able to be validated"},
		{"exp", now - 3600, "the `Expiration` was not able to be validated"},
		{"iat", now + 3600, "the `Issued At` was not able to be validated"},
		{"nonce", "replayed", "the `Nonce` was not able to be validated"},
	}

	jv := newVerifier(ti.URL(), idClaimsToValidate())
	for _, c := range cases {
		claims := ti.idClaims()
		claims[c.claim] = c.value
		token, err := jv.VerifyIdToken(ti.token(t, claims))
		if err == nil || !strings.HasPrefix(err.Error(), c.wantErr) {
			t.Errorf("%s: expected error %q, got %v", c.claim, c.wantErr, err)
		}
		if token == nil || token.Claims == nil {
			t.Errorf("%s: expected decoded claims to be returned alongside the error", c.claim)
		}
	}
}

func Test_verify_id_token_does_not_check_cid(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()

	claimsToValidate := idClaimsToValidate()
	claimsToValidate["cid"] = "expected-cid"
	jv := newVerifier(ti.URL(), claimsToValidate)
	if _, err := jv.VerifyIdToken(ti.token(t, ti.idClaims())); err != nil {
		t.Errorf("id token verification should ignore cid: %s", err)
	}
}

func Test_verify_rejects_token_signed_by_unknown_key(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()
	other := newTestIssuer(t)
	defer other.Close()

	jv := newVerifier(ti.URL(), accessClaimsToValidate())
	forged := other.token(t, ti.accessClaims())

	token, err := jv.VerifyAccessToken(forged)
	if token != nil || err == nil || !strings.HasPrefix(err.Error(), "could not decode token:") {
		t.Errorf("expected decode failure, got %v %v", token, err)
	}

	jv = newVerifier(ti.URL(), idClaimsToValidate())
	token, err = jv.VerifyIdToken(other.token(t, ti.idClaims()))
	if token != nil || err == nil || !strings.HasPrefix(err.Error(), "could not decode token:") {
		t.Errorf("expected decode failure, got %v %v", token, err)
	}
}

func Test_verify_rejects_tampered_payload(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()

	jv := newVerifier(ti.URL(), accessClaimsToValidate())
	parts := strings.Split(ti.token(t, ti.accessClaims()), ".")
	tamperedClaims := ti.accessClaims()
	tamperedClaims["cid"] = "attacker"
	parts[1] = strings.Split(ti.token(t, tamperedClaims), ".")[1]

	if _, err := jv.VerifyAccessToken(strings.Join(parts, ".")); err == nil {
		t.Errorf("tampered token should not verify")
	}
}

func Test_metadata_and_jwks_are_cached(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()

	jv := newVerifier(ti.URL(), accessClaimsToValidate())
	for i := 0; i < 3; i++ {
		if _, err := jv.VerifyAccessToken(ti.token(t, ti.accessClaims())); err != nil {
			t.Fatalf("could not verify access token: %s", err)
		}
	}
	if hits := atomic.LoadInt32(&ti.metadataHits); hits != 1 {
		t.Errorf("expected metadata to be fetched once, got %d", hits)
	}
	if hits := atomic.LoadInt32(&ti.jwksHits); hits != 1 {
		t.Errorf("expected jwks to be fetched once, got %d", hits)
	}
}

func Test_get_metadata_uses_issuer_and_discovery_url(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()

	disc := oidc.Oidc{}
	jv := JwtVerifier{Issuer: ti.URL(), Discovery: disc.New()}
	md, err := jv.New().getMetaData()
	if err != nil {
		t.Fatalf("could not get metadata: %s", err)
	}
	if md["jwks_uri"] != ti.URL()+"/keys" {
		t.Errorf("unexpected jwks_uri: %v", md["jwks_uri"])
	}
}

func Test_get_metadata_returns_error_when_issuer_unreachable(t *testing.T) {
	ti := newTestIssuer(t)
	url := ti.URL()
	ti.Close()

	jv := newVerifier(url, nil)
	_, err := jv.getMetaData()
	if err == nil || !strings.HasPrefix(err.Error(), "request for metadata was not successful:") {
		t.Errorf("expected metadata request error, got %v", err)
	}

	validHeader := encodeHeader(t, map[string]string{"alg": "RS256", "kid": "abc"})
	if _, err := jv.VerifyAccessToken(validHeader + ".payload.signature"); err == nil {
		t.Errorf("expected verification to fail when metadata is unreachable")
	}
	if _, err := jv.VerifyIdToken(validHeader + ".payload.signature"); err == nil {
		t.Errorf("expected verification to fail when metadata is unreachable")
	}
}

func Test_decode_jwt_passes_jwks_uri_to_adaptor(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()

	adaptor := &fakeAdaptor{claims: map[string]interface{}{"sub": "user"}}
	jvs := JwtVerifier{Issuer: ti.URL(), Adaptor: adaptor}
	resp, err := jvs.New().decodeJwt("a.b.c")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if adaptor.jwkUri != ti.URL()+"/keys" {
		t.Errorf("adaptor received jwks uri %q", adaptor.jwkUri)
	}
	if resp.(map[string]interface{})["sub"] != "user" {
		t.Errorf("unexpected decode result: %v", resp)
	}
}

func Test_decode_jwt_wraps_adaptor_errors(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()

	adaptor := &fakeAdaptor{err: errors.New("boom")}
	jvs := JwtVerifier{Issuer: ti.URL(), Adaptor: adaptor}
	_, err := jvs.New().decodeJwt("a.b.c")
	if err == nil || err.Error() != "could not decode token: boom" {
		t.Errorf("expected wrapped adaptor error, got %v", err)
	}
}

func Test_verify_with_custom_adaptor(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.Close()

	adaptor := &fakeAdaptor{}
	jvs := JwtVerifier{Issuer: ti.URL(), ClaimsToValidate: accessClaimsToValidate(), Adaptor: adaptor}
	validHeader := encodeHeader(t, map[string]string{"alg": "RS256", "kid": "abc"})

	// encoding/json decodes numbers as float64, which the exp/iat validators require.
	adaptor.claims = map[string]interface{}{
		"iss": ti.URL(),
		"aud": "api://default",
		"cid": "client-id",
		"exp": float64(time.Now().Unix() + 3600),
		"iat": float64(time.Now().Unix()),
	}
	if _, err := jvs.New().VerifyAccessToken(validHeader + ".payload.signature"); err != nil {
		t.Errorf("expected custom adaptor claims to verify: %s", err)
	}
}
