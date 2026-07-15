package eventpayload_test

import (
	"testing"

	"github.com/Mnexa-AI/e2a/internal/eventpayload"
	"github.com/Mnexa-AI/e2a/internal/webhookpub"
)

func TestStableCatalogPartitionsKnownEvents(t *testing.T) {
	stable := map[string]bool{}
	schemas := map[string]bool{}
	fixtures := map[string]bool{}
	for _, entry := range eventpayload.StableEvents {
		if stable[entry.Type] {
			t.Errorf("duplicate stable event type %q", entry.Type)
		}
		stable[entry.Type] = true
		if entry.SchemaName == "" {
			t.Errorf("stable event %q has no schema name", entry.Type)
		} else if schemas[entry.SchemaName] {
			t.Errorf("duplicate stable schema name %q", entry.SchemaName)
		}
		schemas[entry.SchemaName] = true
		if entry.Payload == nil {
			t.Errorf("stable event %q has no payload type", entry.Type)
		}
		if entry.Fixture == "" {
			t.Errorf("stable event %q has no full fixture", entry.Type)
		} else if fixtures[entry.Fixture] {
			t.Errorf("duplicate stable fixture %q", entry.Fixture)
		}
		fixtures[entry.Fixture] = true
		if entry.MinimalFixture != "" {
			if fixtures[entry.MinimalFixture] {
				t.Errorf("duplicate stable fixture %q", entry.MinimalFixture)
			}
			fixtures[entry.MinimalFixture] = true
		}
	}

	experimental := map[string]bool{}
	for _, typ := range webhookpub.ExperimentalEventTypes {
		experimental[typ] = true
	}
	for _, typ := range webhookpub.AllEventTypes {
		if stable[typ] == experimental[typ] {
			t.Errorf("event %q must be exactly one of stable or experimental", typ)
		}
	}
	if len(stable)+len(experimental) != len(webhookpub.AllEventTypes) {
		t.Errorf("stable (%d) + experimental (%d) != all event types (%d)", len(stable), len(experimental), len(webhookpub.AllEventTypes))
	}
}
