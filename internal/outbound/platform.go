package outbound

import (
	"fmt"
)

// PlatformDisplayName is the display name on platform-originated mail
// (From: "e2a" <noreply@<from_domain>>). Matches the historical test-email
// identity so recipients/agents see the same sender across releases.
const PlatformDisplayName = "e2a"

// PlatformEnvelopeFrom returns the platform/noreply sender address for a
// deployment's outbound from-domain. Single source of truth for the
// "noreply@<from_domain>" identity used by platform-originated messages.
func PlatformEnvelopeFrom(fromDomain string) string {
	return fmt.Sprintf("noreply@%s", fromDomain)
}

// ComposePlatformForAccept composes a PLATFORM-originated outbound message for
// the async accept path WITHOUT submitting it. Unlike ComposeForAccept, the
// sender identity is the platform itself — From: "e2a" <noreply@<from_domain>>
// with a matching envelope MAIL FROM — never an agent, and the agent's own
// address is NOT stripped from the recipient set. This is what the agent test
// send (POST /v1/agents/{email}/test) requires: the message must traverse the
// real external SMTP → inbound route back to the agent's own public address,
// so both the agent-identity compose (which strips the agent's own address —
// "no valid recipients") and the local self-send loopback would defeat it.
//
// The returned bytes flow through the identical durable pipeline as every
// other accepted send: the accept-tx persists Raw/EnvelopeFrom/SentAs and the
// River worker submits via SubmitOnce (which re-attaches the SES config-set
// header, exactly as with ComposeForAccept output).
//
// DKIM: when a key exists for the platform from-domain it is applied, matching
// what relay-From agent sends do; absent a stored key the message goes out
// unsigned here and relies on the relay/SES edge signing — the same behavior
// the legacy synchronous test send had.
func (s *Sender) ComposePlatformForAccept(req SendRequest) (*ComposeResult, error) {
	// Normalize and validate all addresses. No self-alias stripping — the
	// whole point of a platform send is that the agent's own address is a
	// legitimate external recipient.
	to, err := normalizeAddrs(req.To)
	if err != nil {
		return nil, &ValidationError{Message: fmt.Sprintf("invalid To address: %v", err)}
	}
	cc, err := normalizeAddrs(req.CC)
	if err != nil {
		return nil, &ValidationError{Message: fmt.Sprintf("invalid CC address: %v", err)}
	}
	bcc, err := normalizeAddrs(req.BCC)
	if err != nil {
		return nil, &ValidationError{Message: fmt.Sprintf("invalid BCC address: %v", err)}
	}

	// Dedupe within each field, then cross-field (To > CC > BCC) — mirrors compose().
	to = dedupe(to)
	cc = dedupe(cc)
	bcc = dedupe(bcc)
	cc = removeAddrs(cc, to)
	bcc = removeAddrs(bcc, to)
	bcc = removeAddrs(bcc, cc)

	if len(to) == 0 && len(cc) == 0 {
		return nil, &ValidationError{Message: "no valid recipients"}
	}

	envelope := make([]string, 0, len(to)+len(cc)+len(bcc))
	envelope = append(envelope, to...)
	envelope = append(envelope, cc...)
	envelope = append(envelope, bcc...)

	envelopeFrom := PlatformEnvelopeFrom(s.fromDomain)
	headerFrom := fmt.Sprintf("%q <%s>", PlatformDisplayName, envelopeFrom)

	// Reply-To: platform mail defaults replies to the noreply sender (i.e. no
	// override) unless the request carries one.
	replyTo := req.ReplyTo

	var message []byte
	if len(req.Attachments) > 0 {
		message, err = ComposeMessageWithAttachments(headerFrom, to, cc, req.Subject, req.Body, req.HTMLBody, req.ReplyToMessageID, req.References, s.fromDomain, replyTo, req.ConversationID, req.Attachments)
	} else if req.HTMLBody != "" {
		message, err = ComposeMultipartMessage(headerFrom, to, cc, req.Subject, req.Body, req.HTMLBody, req.ReplyToMessageID, req.References, s.fromDomain, replyTo, req.ConversationID)
	} else {
		message, err = ComposeMessage(headerFrom, to, cc, req.Subject, req.Body, "text/plain", req.ReplyToMessageID, req.References, s.fromDomain, replyTo, req.ConversationID)
	}
	if err != nil {
		return nil, fmt.Errorf("compose message: %w", err)
	}

	// Sign with the platform from-domain key when one exists (same fallback
	// signing domain relay-From agent sends use); silently unsigned otherwise.
	if s.dkimLookup != nil {
		if signed, ok := s.signMessage(message, s.fromDomain); ok {
			message = signed
		}
	}

	return &ComposeResult{
		EnvelopeFrom: envelopeFrom,
		Recipients:   envelope,
		SentAs:       "relay",
		Method:       "smtp",
		Raw:          message,
		To:           to,
		CC:           cc,
		BCC:          bcc,
	}, nil
}
