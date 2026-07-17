-- 066_messages_failure_provenance.sql
--
-- Failure provenance + provider-accept evidence for the async-send-contract
-- §3.1 correction rule (falsely-declared terminal failures must be
-- correctable; genuine provider rejections must never be revived):
--
--   * provider_accepted_at — set by the SNS consumer when any correlated
--     post-acceptance SES notification (Send/Delivery/DeliveryDelay/Bounce/
--     Complaint) proves the provider accepted this message's submission. The
--     send worker and the terminal reconciler consult it before declaring an
--     accepted/sending row `failed`, and the worker skips re-submitting a
--     message the provider already has (the SMTP-accept↔mark-sent crash
--     window's duplicate residual).
--
--   * delivery_failure_source — who established a terminal `failed`:
--     'provider' (explicit SES rejection: permanent 5xx on submit, SES
--     Reject) is never corrected; 'local' (retries exhausted on ambiguous
--     errors, outage horizon elapsed, terminal reconciler sweep, trash
--     cancel) is correctable by authoritatively correlated provider
--     sent/delivered evidence. NULL (legacy rows failed before provenance
--     existed) is treated as locally inferred — see
--     internal/delivery/status.go FailureSource.Correctable.
--
-- Both are nullable ADD COLUMNs — metadata-only, no table rewrite on the
-- prod-sized messages table; the CHECK is added NOT VALID (no validation
-- scan; existing rows are all NULL and conform anyway). Idempotent.

ALTER TABLE messages ADD COLUMN IF NOT EXISTS provider_accepted_at    TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS delivery_failure_source TEXT;

ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_delivery_failure_source_check;
ALTER TABLE messages ADD CONSTRAINT messages_delivery_failure_source_check
    CHECK (delivery_failure_source IS NULL OR delivery_failure_source IN ('local','provider'))
    NOT VALID;
