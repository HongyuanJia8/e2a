package eventpayload

// StableEvent describes one GA-frozen event payload contract. It is the
// source consumed by OpenAPI registration and fixture coverage; the event
// publisher's complete vocabulary additionally contains explicitly
// experimental event types.
type StableEvent struct {
	Type           string
	SchemaName     string
	Payload        any
	Fixture        string
	MinimalFixture string
}

// StableEvents is the canonical event-type → payload-schema catalog. Keep the
// slice ordered for deterministic OpenAPI output and documentation tests.
var StableEvents = []StableEvent{
	{"email.received", "EmailReceivedData", EmailReceivedData{}, "email.received.json", "email.received.min.json"},
	{"email.sent", "EmailSentData", EmailSentData{}, "email.sent.json", "email.sent.min.json"},
	{"email.failed", "EmailFailedData", EmailFailedData{}, "email.failed.json", "email.failed.min.json"},
	{"email.delivered", "EmailDeliveredData", EmailDeliveredData{}, "email.delivered.json", "email.delivered.min.json"},
	{"email.bounced", "EmailBouncedData", EmailBouncedData{}, "email.bounced.json", "email.bounced.min.json"},
	{"email.complained", "EmailComplainedData", EmailComplainedData{}, "email.complained.json", "email.complained.min.json"},
	{"domain.sending_verified", "DomainSendingVerifiedData", DomainSendingVerifiedData{}, "domain.sending_verified.json", ""},
	{"domain.sending_failed", "DomainSendingFailedData", DomainSendingFailedData{}, "domain.sending_failed.json", "domain.sending_failed.min.json"},
	{"domain.suppression_added", "DomainSuppressionAddedData", DomainSuppressionAddedData{}, "domain.suppression_added.json", "domain.suppression_added.min.json"},
}
