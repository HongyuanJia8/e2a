package httpapi

// The approve path's 422 recipient_suppressed must interact with
// Idempotency-Key exactly like send's: the refusal happens strictly BEFORE
// any side effect, so runIdempotent RELEASES the key — the 422 is never
// cached, and a later byte-identical retry with the SAME key (after the
// suppression is removed) re-executes and succeeds rather than replaying the
// refusal or tripping idempotency_in_flight/key_reuse.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tokencanopy/e2a/internal/agent"
	"github.com/tokencanopy/e2a/internal/identity"
)

func TestApproveSuppressed422ReleasesIdempotencyKey(t *testing.T) {
	approvals := 0
	srv := testServer(t, func(d *Deps) {
		d.Idempotency = newMemIdem()
		d.ApprovePending = func(ctx context.Context, userID, messageID, expectedAgentEmail string, ovr agent.ApproveOverrides, complete agent.ApproveIdemCompleter) (*identity.Message, *agent.OutboundError) {
			approvals++
			if approvals == 1 {
				// First attempt: a recipient is suppressed — refusal before any
				// side effect, hold left pending, completer NOT invoked.
				return nil, &agent.OutboundError{
					Status: http.StatusUnprocessableEntity,
					Code:   "recipient_suppressed",
					Msg:    "recipient(s) on the suppression list: alice@external.test",
				}
			}
			// Retry after the suppression was removed: approval succeeds.
			sent := &identity.Message{ID: messageID, DeliveryStatus: "accepted", Method: "smtp"}
			if complete != nil {
				if err := complete(ctx, nil, sent); err != nil {
					t.Fatalf("complete approval idempotency in tx: %v", err)
				}
			}
			return sent, nil
		}
	})

	rawBody := []byte(`{}`)
	approve := func() (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/reviews/msg_pending/approve", bytes.NewReader(rawBody))
		req.Header.Set("Authorization", "Bearer good")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "supp-retry-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("approve request: %v", err)
		}
		defer resp.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		return resp.StatusCode, body
	}

	code, body := approve()
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("first approve = %d %v, want 422", code, body)
	}
	if errObj, _ := body["error"].(map[string]any); errObj == nil || errObj["code"] != "recipient_suppressed" {
		t.Fatalf("first approve error = %v, want code recipient_suppressed", body)
	}

	// Same key, byte-identical body, after the suppression cleared: must
	// RE-EXECUTE (released key) and succeed — not replay the 422, not 409/422
	// on the key.
	code, body = approve()
	if code != http.StatusAccepted {
		t.Fatalf("retry after un-suppression = %d %v, want 202 (key released by the refusal)", code, body)
	}
	if approvals != 2 {
		t.Fatalf("approvals = %d, want 2 (the refused attempt must not be cached)", approvals)
	}
}

// The suppression refusal is a declared contract on approveReview: the 422
// response must document recipient_suppressed (alongside the idempotency
// codes) and the operation description must state that the final merged
// recipient set is re-checked and a refusal leaves the hold pending_review.
func TestSpecApproveDeclaresRecipientSuppressed(t *testing.T) {
	doc := renderSpec(t)
	operation := specOperation(t, doc, "approveReview")
	description, _ := operation["description"].(string)
	requireContractText(t, "approveReview", description,
		"suppression list",
		"recipient_suppressed",
		"pending_review",
	)
	responseDescription := specResponseDescription(t, operation, "422")
	requireContractText(t, "approveReview 422", responseDescription,
		"recipient_suppressed",
		"idempotency_key_reuse",
	)
}
