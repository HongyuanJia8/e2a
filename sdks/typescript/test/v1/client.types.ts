import type { FieldError } from "../../src/v1/generated/models/FieldError.js";
import type { ListMessagesParams } from "../../src/v1/index.js";
import type { WebhookEvent } from "../../src/v1/webhook-signature.js";
import type { WSEvent } from "../../src/v1/ws.js";

const senderFilter: ListMessagesParams = { from_: "alice@example.com" };
void senderFilter;

// The pre-GA breaking rename intentionally removes the old public spelling.
// @ts-expect-error `from` is the wire name; SDK callers use `from_`.
const removedSenderFilter: ListMessagesParams = { from: "alice@example.com" };
void removedSenderFilter;

const validationField: FieldError = { location: "", message: "invalid request" };
void validationField;

// @ts-expect-error location is required by the GA validation contract.
const missingValidationLocation: FieldError = { message: "invalid request" };
void missingValidationLocation;

const eventEnvelope: WebhookEvent = {
  type: "email.received",
  id: "evt_1",
  schema_version: "1",
  created_at: "2026-07-01T10:30:00Z",
  data: {},
};
const wsEnvelope: WSEvent = eventEnvelope;
void wsEnvelope;

// @ts-expect-error all five core envelope fields are required.
const incompleteEventEnvelope: WebhookEvent = { type: "email.received", data: {} };
void incompleteEventEnvelope;
