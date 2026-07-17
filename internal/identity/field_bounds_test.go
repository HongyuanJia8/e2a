package identity_test

import (
	"context"
	"strings"
	"testing"

	"github.com/tokencanopy/e2a/internal/identity"
	"github.com/tokencanopy/e2a/internal/testutil"
)

// ValidateAgentName counts Unicode code points (runes), not bytes — matching
// the OpenAPI maxLength semantics of the /v1 request schemas (Huma validates
// maxLength with utf8.RuneCountInString). A 200-code-point CJK name is 600
// bytes; byte-counting would reject it and the store would disagree with the
// schema that already admitted the request.
func TestValidateAgentNameRuneSemantics(t *testing.T) {
	atLimit := strings.Repeat("日", identity.MaxAgentNameLen) // 200 code points, 600 bytes
	if err := identity.ValidateAgentName(atLimit); err != nil {
		t.Fatalf("name at %d code points must pass, got %v", identity.MaxAgentNameLen, err)
	}
	if err := identity.ValidateAgentName(strings.Repeat("日", identity.MaxAgentNameLen+1)); err == nil {
		t.Fatal("name over the code-point limit must fail")
	}
	// Plain ASCII at the limit stays valid (bytes == runes there).
	if err := identity.ValidateAgentName(strings.Repeat("a", identity.MaxAgentNameLen)); err != nil {
		t.Fatalf("ASCII name at limit must pass, got %v", err)
	}
}

// The request-edge conversation_id bound (200) is validation only — NO
// database constraint. A pre-existing stored value longer than the cap must
// remain readable: detail and list reads return it intact. (Writing one via
// direct SQL simulates rows persisted before the bound existed.)
func TestOverlongStoredConversationIDStillReadable(t *testing.T) {
	pool := testutil.TestDB(t)
	store := identity.NewStore(pool)
	ctx := context.Background()
	agentID := convoTestSetup(t, store, "overlong-conv")

	out, err := store.CreateOutboundMessage(
		ctx, agentID, []string{"alice@gmail.com"}, nil, nil,
		"Hello", "send", "smtp", "<overlong-conv-1@x>", "conv-ok", nil,
	)
	if err != nil {
		t.Fatalf("CreateOutboundMessage: %v", err)
	}

	overlong := strings.Repeat("x", 5000) // far past the 200 request-edge cap
	if _, err := pool.Exec(ctx, `UPDATE messages SET conversation_id = $1 WHERE id = $2`, overlong, out.ID); err != nil {
		t.Fatalf("direct UPDATE: %v", err)
	}

	got, err := store.GetMessageWithContent(ctx, out.ID, agentID)
	if err != nil {
		t.Fatalf("GetMessageWithContent: %v", err)
	}
	if got.ConversationID != overlong {
		t.Errorf("detail read: conversation_id truncated or altered (len %d, want %d)", len(got.ConversationID), len(overlong))
	}

	msgs, err := store.GetMessagesByAgent(ctx, identity.MessageListFilter{
		AgentID: agentID, Direction: "outbound", Limit: 10,
	})
	if err != nil {
		t.Fatalf("GetMessagesByAgent: %v", err)
	}
	found := false
	for _, m := range msgs {
		if m.ID == out.ID {
			found = true
			if m.ConversationID != overlong {
				t.Errorf("list read: conversation_id truncated or altered (len %d, want %d)", len(m.ConversationID), len(overlong))
			}
		}
	}
	if !found {
		t.Fatalf("message %s with over-long conversation_id not returned by list", out.ID)
	}
}
