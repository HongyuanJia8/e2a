package outbound

import (
	"strings"
	"testing"

	"github.com/tokencanopy/e2a/internal/config"
)

func platformSender() *Sender {
	return NewSender(NewSMTPRelay(&config.OutboundSMTPConfig{}), "test.e2a.dev")
}

// TestComposePlatformForAccept_PlatformIdentity pins the platform-originated
// sender contract: envelope + header From are noreply@<from_domain> (never an
// agent identity) and the recipient — even an address that WOULD be a self-send
// for the owning agent — is preserved on the envelope, not stripped.
func TestComposePlatformForAccept_PlatformIdentity(t *testing.T) {
	s := platformSender()
	comp, err := s.ComposePlatformForAccept(SendRequest{
		To:             []string{"bot@customer.example.com"},
		Subject:        "Test email from e2a",
		Body:           "hello",
		ConversationID: "conv_abc123",
	})
	if err != nil {
		t.Fatalf("ComposePlatformForAccept: %v", err)
	}
	if comp.EnvelopeFrom != "noreply@test.e2a.dev" {
		t.Errorf("EnvelopeFrom = %q, want noreply@test.e2a.dev", comp.EnvelopeFrom)
	}
	if len(comp.Recipients) != 1 || comp.Recipients[0] != "bot@customer.example.com" {
		t.Errorf("Recipients = %v, want [bot@customer.example.com]", comp.Recipients)
	}
	if comp.Method != "smtp" || comp.SentAs != "relay" {
		t.Errorf("Method/SentAs = %q/%q, want smtp/relay", comp.Method, comp.SentAs)
	}
	raw := string(comp.Raw)
	if !strings.Contains(raw, `From: "e2a" <noreply@test.e2a.dev>`) {
		t.Errorf("raw From header missing platform identity:\n%s", raw)
	}
	if !strings.Contains(raw, "To: bot@customer.example.com") {
		t.Errorf("raw To header missing the agent recipient:\n%s", raw)
	}
	if !strings.Contains(strings.ToLower(raw), "x-e2a-conversation-id: conv_abc123") {
		t.Errorf("raw missing the conversation thread anchor header:\n%s", raw)
	}
}

// TestComposePlatformForAccept_NoRecipients rejects an empty visible-recipient
// set as a ValidationError (mapped to 400 by callers).
func TestComposePlatformForAccept_NoRecipients(t *testing.T) {
	s := platformSender()
	if _, err := s.ComposePlatformForAccept(SendRequest{Subject: "x", Body: "y"}); !IsValidationError(err) {
		t.Fatalf("err = %v, want ValidationError for no recipients", err)
	}
}
