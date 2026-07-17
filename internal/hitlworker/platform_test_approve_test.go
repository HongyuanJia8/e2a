package hitlworker_test

import (
	"context"
	"testing"

	"github.com/tokencanopy/e2a/internal/identity"
)

// TestWorkerAutoApproveAsync_PlatformTestStaysExternalSMTP: TTL auto-approval
// of a held platform test (type="test") must preserve the platform-originated
// external SMTP semantics — queued onto QueueOutbound with the noreply@
// envelope — and must NOT be rerouted to the local self-send loopback just
// because its recipient is the agent's own address. Loopback here would
// fabricate the inbound copy locally and silently stop exercising the real
// inbound route the test exists to verify.
func TestWorkerAutoApproveAsync_PlatformTestStaysExternalSMTP(t *testing.T) {
	w, store, pool, smtpDone := setupWorker(t)
	ctx := context.Background()

	agent := prepareAgent(t, store, "test-platform", identity.HITLExpirationApprove)
	enq := &fakeEnq{}
	w.SetOutboundEnqueuer(enq)

	msg, err := store.CreatePendingOutboundMessage(ctx, agent.ID,
		[]string{agent.EmailAddress()}, nil, nil,
		"Test email from e2a", "test body", "", nil, "test", "", "", "", 60)
	if err != nil {
		t.Fatal(err)
	}
	backdateExpiry(t, pool, msg.ID)

	w.RunOnce(ctx)

	// Queued, not sent inline and not loopback-delivered.
	if msgs := smtpDone(); len(msgs) != 0 {
		t.Fatalf("async auto-approve must NOT send inline, got %d SMTP messages", len(msgs))
	}
	if len(enq.calls) != 1 || enq.calls[0] != msg.ID {
		t.Fatalf("EnqueueSendTx calls = %v, want [%s] (platform test must be queued)", enq.calls, msg.ID)
	}

	var status, deliveryStatus, envelopeFrom, method string
	var sendJobID *int64
	if err := pool.QueryRow(ctx,
		`SELECT status, COALESCE(delivery_status,''), COALESCE(envelope_from,''), method, send_job_id FROM messages WHERE id=$1`, msg.ID,
	).Scan(&status, &deliveryStatus, &envelopeFrom, &method, &sendJobID); err != nil {
		t.Fatal(err)
	}
	if status != identity.MessageStatusReviewExpiredApproved {
		t.Errorf("status = %q, want %q", status, identity.MessageStatusReviewExpiredApproved)
	}
	if deliveryStatus != "accepted" {
		t.Errorf("delivery_status = %q, want accepted", deliveryStatus)
	}
	if envelopeFrom != "noreply@test.e2a.dev" {
		t.Errorf("envelope_from = %q, want noreply@test.e2a.dev (platform-originated)", envelopeFrom)
	}
	if method != "smtp" {
		t.Errorf("method = %q, want smtp (not loopback)", method)
	}
	if sendJobID == nil || *sendJobID != 7777 {
		t.Errorf("send_job_id = %v, want 7777", sendJobID)
	}

	// No locally-fabricated inbound twin.
	var inbound int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM messages WHERE agent_id=$1 AND direction='inbound'`, agent.ID,
	).Scan(&inbound); err != nil {
		t.Fatal(err)
	}
	if inbound != 0 {
		t.Errorf("inbound rows = %d, want 0 (TTL approval must not loopback a platform test)", inbound)
	}
}
