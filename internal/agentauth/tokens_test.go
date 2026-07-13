package agentauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

const testIssuer = "https://api.e2a.dev"

func testSigner(t *testing.T) *Signer {
	t.Helper()
	pem, _ := genPKCS1PEM(t)
	s, err := NewSigner(pem, "v1")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestSignVerify_IdentityAssertion(t *testing.T) {
	s := testSigner(t)
	tok, exp, err := s.SignIdentityAssertion("support@acme.com", "agent", 3, testIssuer)
	if err != nil {
		t.Fatalf("SignIdentityAssertion: %v", err)
	}
	if time.Until(exp) < 29*24*time.Hour {
		t.Errorf("identity_assertion TTL too short: %v", time.Until(exp))
	}
	got, err := s.VerifyToken(tok, TypIdentityAssertion, testIssuer)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if got.Subject != "support@acme.com" || got.Scope != "agent" || got.AssertionVersion != 3 || got.Type != TypIdentityAssertion {
		t.Errorf("claims = %+v", got)
	}
}

func TestSignVerify_AccessToken(t *testing.T) {
	s := testSigner(t)
	tok, exp, err := s.SignAccessToken("bot@acme.com", "agent", 1, testIssuer)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if d := time.Until(exp); d > 16*time.Minute || d < 14*time.Minute {
		t.Errorf("access_token TTL = %v, want ~15m", d)
	}
	got, err := s.VerifyToken(tok, TypAccessToken, testIssuer)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if got.Subject != "bot@acme.com" || got.Type != TypAccessToken {
		t.Errorf("claims = %+v", got)
	}
}

// TestVerify_TypeConfusion: an access_token must NOT verify as an
// identity_assertion (and vice versa) — the typ claim is load-bearing, so a
// short-lived access token can't be replayed as the long-lived credential.
func TestVerify_TypeConfusion(t *testing.T) {
	s := testSigner(t)
	at, _, _ := s.SignAccessToken("x@acme.com", "agent", 1, testIssuer)
	if _, err := s.VerifyToken(at, TypIdentityAssertion, testIssuer); err == nil {
		t.Error("access_token must not verify as identity_assertion")
	}
	ia, _, _ := s.SignIdentityAssertion("x@acme.com", "agent", 1, testIssuer)
	if _, err := s.VerifyToken(ia, TypAccessToken, testIssuer); err == nil {
		t.Error("identity_assertion must not verify as access_token")
	}
}

// TestVerify_WrongIssuerOrAudience: a token minted for a different AS host must
// be rejected (prevents cross-deployment token replay).
func TestVerify_WrongIssuerOrAudience(t *testing.T) {
	s := testSigner(t)
	tok, _, _ := s.SignAccessToken("x@acme.com", "agent", 1, testIssuer)
	if _, err := s.VerifyToken(tok, TypAccessToken, "https://evil.example.com"); err == nil {
		t.Error("token must not verify against a different issuer/audience")
	}
}

// TestVerify_WrongKey: a token signed by a different key must not verify.
func TestVerify_WrongKey(t *testing.T) {
	s1 := testSigner(t)
	s2 := testSigner(t)
	tok, _, _ := s1.SignAccessToken("x@acme.com", "agent", 1, testIssuer)
	if _, err := s2.VerifyToken(tok, TypAccessToken, testIssuer); err == nil {
		t.Error("token signed by another key must not verify")
	}
}

func TestVerify_DisabledSigner(t *testing.T) {
	disabled, _ := NewSigner("", "")
	if _, _, err := disabled.SignAccessToken("x", "agent", 1, testIssuer); err != ErrSigningDisabled {
		t.Errorf("sign on disabled = %v, want ErrSigningDisabled", err)
	}
	if _, err := disabled.VerifyToken("whatever", TypAccessToken, testIssuer); err != ErrSigningDisabled {
		t.Errorf("verify on disabled = %v, want ErrSigningDisabled", err)
	}
}

// TestVerify_RejectsAlgConfusion: the two classic JWT forgery attacks must be
// rejected. VerifyToken pins alg=RS256, so neither an unsigned `alg:none` token
// nor an HS256 token whose MAC is keyed on the server's PUBLIC key (the RSA/HMAC
// confusion) can verify — regardless of go-jose's own key-type binding.
func TestVerify_RejectsAlgConfusion(t *testing.T) {
	s := testSigner(t)
	now := time.Now()
	// Otherwise-valid claims, so only the forged `alg` differs from a good token.
	payload, err := json.Marshal(map[string]any{
		"iss":               testIssuer,
		"aud":               testIssuer,
		"sub":               "x@acme.com",
		"iat":               now.Unix(),
		"nbf":               now.Unix(),
		"exp":               now.Add(time.Hour).Unix(),
		"typ":               TypAccessToken,
		"scope":             "agent",
		"assertion_version": 1,
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

	// 1) alg:none — unsecured JWS, empty signature.
	noneTok := b64([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + b64(payload) + "."
	if _, err := s.VerifyToken(noneTok, TypAccessToken, testIssuer); err == nil {
		t.Error("alg:none token verified; want rejected")
	}

	// 2) alg:HS256 with the HMAC keyed on the server's PUBLIC key (PKIX PEM) —
	// a *validly* MAC'd token that must still be rejected because we pin RS256.
	pub, err := x509.MarshalPKIXPublicKey(s.priv.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
	signingInput := b64([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + b64(payload)
	mac := hmac.New(sha256.New, pubPEM)
	mac.Write([]byte(signingInput))
	hs256Tok := signingInput + "." + b64(mac.Sum(nil))
	if _, err := s.VerifyToken(hs256Tok, TypAccessToken, testIssuer); err == nil {
		t.Error("HS256-confusion token verified; want rejected")
	}
}

func TestVerify_GarbageToken(t *testing.T) {
	s := testSigner(t)
	for _, bad := range []string{"", "not-a-jwt", "a.b.c", strings.Repeat("x", 50)} {
		if _, err := s.VerifyToken(bad, TypAccessToken, testIssuer); err == nil {
			t.Errorf("garbage %q verified", bad)
		}
	}
}
