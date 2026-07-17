package delivery

import "testing"

func TestMergeMonotonic(t *testing.T) {
	tests := []struct {
		name              string
		current, incoming Status
		want              Status
	}{
		{"queued→sent", StatusQueued, StatusSent, StatusSent},
		{"sent→delivered", StatusSent, StatusDelivered, StatusDelivered},
		{"sent→bounced", StatusSent, StatusBounced, StatusBounced},
		{"delivered→bounced (bounce wins)", StatusDelivered, StatusBounced, StatusBounced},
		{"bounced→complained (complaint wins)", StatusBounced, StatusComplained, StatusComplained},
		// The load-bearing invariant: a late lower-rank event never regresses a terminal status.
		{"complained NOT clobbered by late delivered", StatusComplained, StatusDelivered, StatusComplained},
		{"bounced NOT clobbered by late delivered", StatusBounced, StatusDelivered, StatusBounced},
		{"delivered NOT regressed by late deferred", StatusDelivered, StatusDeferred, StatusDelivered},
		{"deferred→delivered (resolution wins)", StatusDeferred, StatusDelivered, StatusDelivered},
		{"duplicate delivered is idempotent", StatusDelivered, StatusDelivered, StatusDelivered},
		{"empty current accepts any valid", Status(""), StatusSent, StatusSent},
		{"invalid incoming is ignored", StatusDelivered, Status("garbage"), StatusDelivered},
		// Failure precedence (async-send-contract §3.1): a failed write must
		// never clobber a compliance-critical bounce/complaint…
		{"complained NOT clobbered by late failed", StatusComplained, StatusFailed, StatusComplained},
		{"bounced NOT clobbered by late failed", StatusBounced, StatusFailed, StatusBounced},
		// …but plain-Merge delivery feedback must not silently erase a failure
		// either — correction is the explicit provenance-gated exception
		// (ResolveMessageRollup), never the default merge.
		{"failed NOT corrected by plain-merge delivered", StatusFailed, StatusDelivered, StatusFailed},
		{"failed NOT corrected by plain-merge sent", StatusFailed, StatusSent, StatusFailed},
		{"failed upgraded by bounce (provider disposition wins)", StatusFailed, StatusBounced, StatusBounced},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Merge(tc.current, tc.incoming); got != tc.want {
				t.Errorf("Merge(%q,%q) = %q, want %q", tc.current, tc.incoming, got, tc.want)
			}
		})
	}
}

// TestResolveMessageRollup pins the async-send-contract §3.1 correction rule:
// authoritatively correlated provider evidence corrects a locally inferred
// failed, a provider-confirmed failed is never revived, and non-failed rows
// keep the plain rollup semantics.
func TestResolveMessageRollup(t *testing.T) {
	tests := []struct {
		name    string
		current Status
		source  FailureSource
		rollup  Status
		want    Status
	}{
		// The load-bearing correction: local failed + correlated delivered.
		{"local failed corrected by delivered", StatusFailed, FailureSourceLocal, StatusDelivered, StatusDelivered},
		{"local failed corrected by sent", StatusFailed, FailureSourceLocal, StatusSent, StatusSent},
		{"local failed corrected by deferred", StatusFailed, FailureSourceLocal, StatusDeferred, StatusDeferred},
		{"local failed corrected by bounced (truthful post-accept outcome)", StatusFailed, FailureSourceLocal, StatusBounced, StatusBounced},
		// Legacy rows (failed before provenance existed) stay correctable.
		{"unknown-provenance failed corrected by delivered", StatusFailed, FailureSource(""), StatusDelivered, StatusDelivered},
		// A provider-confirmed failure is never revived.
		{"provider failed NOT corrected by delivered", StatusFailed, FailureSourceProvider, StatusDelivered, StatusFailed},
		{"provider failed NOT corrected by sent", StatusFailed, FailureSourceProvider, StatusSent, StatusFailed},
		// A rollup that does not prove acceptance cannot correct anything.
		{"local failed kept when rollup is failed (Reject)", StatusFailed, FailureSourceLocal, StatusFailed, StatusFailed},
		{"local failed kept when rollup is empty-ish accepted", StatusFailed, FailureSourceLocal, StatusAccepted, StatusFailed},
		// Non-failed current: rollup is authoritative (existing semantics).
		{"sent takes rollup delivered", StatusSent, FailureSource(""), StatusDelivered, StatusDelivered},
		{"sending takes rollup failed (Reject rollup)", StatusSending, FailureSource(""), StatusFailed, StatusFailed},
		{"complained keeps complained rollup", StatusComplained, FailureSource(""), StatusComplained, StatusComplained},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveMessageRollup(tc.current, tc.source, tc.rollup); got != tc.want {
				t.Errorf("ResolveMessageRollup(%q,%q,%q) = %q, want %q", tc.current, tc.source, tc.rollup, got, tc.want)
			}
		})
	}
}

func TestFailureSourceCorrectable(t *testing.T) {
	if FailureSourceProvider.Correctable() {
		t.Error("provider-confirmed failure must not be correctable")
	}
	if !FailureSourceLocal.Correctable() {
		t.Error("locally inferred failure must be correctable")
	}
	if !FailureSource("").Correctable() {
		t.Error("legacy unknown provenance must be correctable (pre-provenance false failures)")
	}
}

func TestStatusTerminal(t *testing.T) {
	terminal := []Status{StatusDelivered, StatusBounced, StatusComplained, StatusFailed}
	nonTerminal := []Status{StatusQueued, StatusSent, StatusDeferred}
	for _, s := range terminal {
		if !s.Terminal() {
			t.Errorf("%q should be terminal", s)
		}
	}
	for _, s := range nonTerminal {
		if s.Terminal() {
			t.Errorf("%q should not be terminal", s)
		}
	}
}
