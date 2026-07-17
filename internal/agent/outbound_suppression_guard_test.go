package agent_test

// End-to-end (real store adapter + real DB) coverage of the SendWorker's
// pre-provider suppression guard: a suppression added AFTER a send was
// durably accepted + queued — approval or direct — still prevents provider
// I/O; the row records a durable terminal failure and email.failed fires.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/tokencanopy/e2a/internal/agent"
	"github.com/tokencanopy/e2a/internal/outbound"
	"github.com/tokencanopy/e2a/internal/outboundsend"
	"github.com/tokencanopy/e2a/internal/usage"
	"github.com/tokencanopy/e2a/internal/webhookpub"
)

// countingDeliverer records provider submits so the guard can assert zero I/O.
type countingDeliverer struct {
	calls int
	out   outboundsend.DeliverOutcome
}

func (d *countingDeliverer) Deliver(_ context.Context, _ *outboundsend.SendJob) outboundsend.DeliverOutcome {
	d.calls++
	return d.out
}

func TestSendWorker_SuppressionAddedAfterAcceptPreventsProviderIO(t *testing.T) {
	api, store, outbox, _ := setupAsyncAPI(t)
	ctx := context.Background()
	user, ag := selfAgent(t, store, "suppafterqueue")

	// Accept + queue while the recipient is clean.
	res, oerr := api.DeliverOutbound(ctx, user, ag, outbound.SendRequest{
		To: []string{"victim@external.test"}, Subject: "queued then suppressed", Body: "x",
	}, "send", "", nil, nil)
	if oerr != nil {
		t.Fatalf("DeliverOutbound: %+v", oerr)
	}
	if res.Status != "accepted" {
		t.Fatalf("Status = %q, want accepted", res.Status)
	}

	// Suppression lands between accept and the worker run (e.g. a bounce or a
	// manual add) — case-varied to exercise normalization.
	if _, err := store.AddSuppression(ctx, user.ID, "Victim@External.TEST", "complaint", "complaint", ""); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}

	deliverer := &countingDeliverer{out: outboundsend.DeliverOutcome{ProviderMessageID: "must-not-happen"}}
	worker := outboundsend.NewSendWorker(
		agent.NewOutboundSendStore(store, outbox, usage.NewNoopUsageTracker()), deliverer)
	if err := worker.Work(ctx, workerJob(res.MessageID, 1)); err == nil {
		t.Fatal("suppressed send must cancel the job (non-nil error)")
	}

	if deliverer.calls != 0 {
		t.Fatalf("provider Deliver called %d times, want zero", deliverer.calls)
	}
	var deliveryStatus, detail string
	if err := store.WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT delivery_status, COALESCE(delivery_detail,'') FROM messages WHERE id=$1`,
			res.MessageID,
		).Scan(&deliveryStatus, &detail)
	}); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if deliveryStatus != "failed" {
		t.Errorf("delivery_status = %q, want failed (durable terminal failure)", deliveryStatus)
	}
	if !strings.Contains(detail, "recipient_suppressed") || !strings.Contains(detail, "victim@external.test") {
		t.Errorf("delivery_detail = %q, want recipient_suppressed naming the address", detail)
	}
	if n := countEvents(t, store, ag.UserID, webhookpub.EventEmailFailed); n != 1 {
		t.Errorf("email.failed events = %d, want 1", n)
	}
	if n := countEvents(t, store, ag.UserID, webhookpub.EventEmailSent); n != 0 {
		t.Errorf("email.sent events = %d, want 0", n)
	}
}
