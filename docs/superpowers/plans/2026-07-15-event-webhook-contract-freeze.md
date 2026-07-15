# Event and Webhook Contract Freeze Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze e2a's open event envelope, stable event-to-data schema mapping, webhook signing and delivery behavior, and WebSocket contract across all supported surfaces.

**Architecture:** A single `internal/eventpayload` catalog supplies stable event names, payload types, OpenAPI component names, and fixtures. Huma publishes an open `EventEnvelope` with a non-constraining `x-e2a-event-data-schemas` map; golden fixtures validate against both that envelope and their mapped payload schema. Focused Go, TypeScript, Python, and CLI tests pin signing, retries, required envelope fields, forward compatibility, and close-code behavior.

**Tech Stack:** Go 1.25, Huma/OpenAPI, River, TypeScript/Vitest, Python/pytest/mypy.

---

### Task 1: Centralize the stable-event catalog

**Files:**
- Create: `internal/eventpayload/catalog.go`
- Create: `internal/eventpayload/catalog_test.go`
- Modify: `internal/eventpayload/golden_test.go`
- Modify: `internal/httpapi/eventpayload_schemas.go`
- Test: `internal/httpapi/eventpayload_schemas_test.go`

- [ ] **Step 1: Write the failing catalog coverage test**

```go
func TestStableCatalogPartitionsKnownEvents(t *testing.T) {
    stable := map[string]bool{}
    for _, entry := range eventpayload.StableEvents {
        if stable[entry.Type] { t.Fatalf("duplicate stable event %q", entry.Type) }
        stable[entry.Type] = true
    }
    experimental := map[string]bool{}
    for _, typ := range webhookpub.ExperimentalEventTypes { experimental[typ] = true }
    for _, typ := range webhookpub.AllEventTypes {
        if stable[typ] == experimental[typ] {
            t.Errorf("event %q must be exactly one of stable or experimental", typ)
        }
    }
}
```

- [ ] **Step 2: Verify it fails**

Run: `go test ./internal/eventpayload ./internal/httpapi`

Expected: FAIL because `eventpayload.StableEvents` is undefined.

- [ ] **Step 3: Add the catalog**

```go
type StableEvent struct {
    Type           string
    SchemaName     string
    Payload        any
    Fixture        string
    MinimalFixture string
}

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
```

- [ ] **Step 4: Replace duplicated registration and coverage lists**

Make `registerEventPayloadSchemas` and `TestGoldenFixtures` iterate the catalog. Keep beta classification in `webhookpub.ExperimentalEventTypes` and assert schema/fixture uniqueness.

- [ ] **Step 5: Verify and commit**

Run: `go test ./internal/eventpayload ./internal/httpapi`

Expected: PASS.

```bash
git add internal/eventpayload internal/httpapi/eventpayload_schemas.go internal/httpapi/eventpayload_schemas_test.go
git commit -m "refactor: centralize stable event catalog"
```

### Task 2: Publish and validate the open EventEnvelope

**Files:**
- Modify: `internal/httpapi/eventpayload_schemas.go`
- Modify: `internal/httpapi/eventpayload_schemas_test.go`
- Create: `internal/httpapi/event_envelope_schema_test.go`
- Modify: `internal/eventpayload/golden_test.go`
- Modify: `api/openapi.yaml`

- [ ] **Step 1: Write failing schema tests**

Assert `EventEnvelope` requires `type`, `id`, `schema_version`, `created_at`, and `data`; keeps `type` and `schema_version` as open strings; has open envelope/data objects; has no `oneOf`, `anyOf`, or discriminator; and maps all stable events through `x-e2a-event-data-schemas`.

```go
mapping := envelope.Properties["data"].Extensions["x-e2a-event-data-schemas"].(map[string]any)
for _, entry := range eventpayload.StableEvents {
    want := "#/components/schemas/" + entry.SchemaName
    if mapping[entry.Type] != want { t.Errorf("mapping[%s] = %v, want %s", entry.Type, mapping[entry.Type], want) }
}
```

- [ ] **Step 2: Verify failure**

Run: `go test ./internal/httpapi -run 'TestEventEnvelope|TestEventPayload'`

Expected: FAIL because `EventEnvelope` is absent.

- [ ] **Step 3: Register the documentation schema and mapping**

```go
type eventEnvelopeSchema struct {
    Type          string         `json:"type" doc:"Open event type; tolerate unknown values."`
    ID            string         `json:"id"`
    SchemaVersion string         `json:"schema_version" doc:"Open version string; the current server emits 1."`
    CreatedAt     time.Time      `json:"created_at" format:"date-time"`
    Data          map[string]any `json:"data" nullable:"false"`
}
```

Register it under the exact name `EventEnvelope`, open all object nodes, and stamp catalog-derived JSON Pointer strings on `data`. Do not add composition keywords.

- [ ] **Step 4: Validate every golden fixture against emitted schemas**

Decode each fixture to `any`, validate the full object using Huma `Validate` against `EventEnvelope`, resolve the mapping for its `type`, and validate `data` against that component. Add an unknown future event with `schema_version: "2"` and unknown envelope/data fields; it must pass only the generic envelope.

- [ ] **Step 5: Verify, regenerate, and commit**

Run: `go test ./internal/eventpayload ./internal/httpapi`

Run the repository OpenAPI generation target, then: `make spec-check`

Expected: PASS.

```bash
git add internal/httpapi internal/eventpayload api/openapi.yaml
git commit -m "feat: publish open event envelope contract"
```

### Task 3: Freeze webhook retry, signing, and headers

**Files:**
- Modify: `internal/webhookdelivery/worker.go`
- Modify: `internal/webhookdelivery/worker_test.go`
- Modify: `internal/webhook/subscriber_deliverer_test.go`
- Create: `internal/webhook/testdata/signing-vector.json`
- Modify: `sdks/typescript/test/v1/webhook-signature.test.ts`
- Modify: `sdks/python/tests/test_webhook_signature.py`

- [ ] **Step 1: Write the retry test exposing the index bug**

```go
want := []time.Duration{time.Minute, 5*time.Minute, 15*time.Minute, time.Hour, 4*time.Hour, 8*time.Hour, 16*time.Hour}
for i, delay := range want {
    got := time.Until(worker.NextRetry(job("id", i+1)))
    if abs(got-delay) > time.Second { t.Errorf("attempt %d: got %v want %v", i+1, got, delay) }
}
```

Pin `MaxDeliveryAttempts == 8` and total elapsed delay `29h21m`.

- [ ] **Step 2: Verify failure and fix indexing**

Run: `go test ./internal/webhookdelivery -run 'NextRetry|Retry'`

Expected: FAIL because attempt one currently selects five minutes.

```go
var retryBackoffs = []time.Duration{
    time.Minute, 5*time.Minute, 15*time.Minute, time.Hour,
    4*time.Hour, 8*time.Hour, 16*time.Hour,
}

func (w *DeliverWorker) NextRetry(job *river.Job[WebhookDeliverArgs]) time.Time {
    i := job.Attempt - 1
    if i < 0 || i >= len(retryBackoffs) { return time.Time{} }
    return time.Now().Add(retryBackoffs[i])
}
```

- [ ] **Step 3: Pin headers and response classification**

Test exact `Content-Type`, `X-E2A-Signature`, `X-E2A-Event-Type`, `X-E2A-Schema-Version`, and `User-Agent`. Test every 2xx as success and representative network/3xx/4xx/5xx outcomes as retryable failure.

- [ ] **Step 4: Add a shared signing vector**

Commit fixed raw body, timestamp, current/previous secrets, and expected single/dual signature headers. Go, TypeScript, and Python verify the same vector, raw-byte sensitivity, constant-time matching behavior, 300-second replay tolerance, and 24-hour dual-sign semantics.

- [ ] **Step 5: Verify and commit**

Run: `go test ./internal/webhook ./internal/webhookdelivery`

Run: `npm test --workspace @e2a/sdk -- --run webhook-signature`

Run: `cd sdks/python && pytest tests/test_webhook_signature.py -q`

Expected: PASS.

```bash
git add internal/webhook internal/webhookdelivery sdks/typescript/test/v1/webhook-signature.test.ts sdks/python/tests/test_webhook_signature.py
git commit -m "fix: freeze webhook signing and retry envelope"
```

### Task 4: Require SDK envelope fields while accepting future versions

**Files:**
- Modify: `sdks/typescript/src/v1/webhook-signature.ts`
- Modify: `sdks/typescript/test/v1/webhook-payloads.test.ts`
- Modify: `sdks/typescript/test/v1/ws.test.ts`
- Modify: `sdks/python/src/e2a/v1/webhook_signature.py`
- Modify: `sdks/python/src/e2a/v1/websocket.py`
- Modify: `sdks/python/tests/test_webhook_payloads.py`
- Modify: `sdks/python/tests/test_v1_websocket.py`
- Modify: existing TypeScript and Python type-check fixtures

- [ ] **Step 1: Write failing required-field and future-version tests**

TypeScript type tests reject missing `id`, `schema_version`, or `created_at`. Runtime constructors reject verified envelopes missing any core field. A known `type` with version `"2"` parses generically but does not narrow; unknown types and unknown fields remain accepted.

- [ ] **Step 2: Verify failures**

Run: `npm test --workspace @e2a/sdk -- --run 'webhook-payloads|ws'`

Run: `cd sdks/python && pytest tests/test_webhook_payloads.py tests/test_v1_websocket.py -q`

Expected: FAIL because envelope fields are optional and guards check only `type`.

- [ ] **Step 3: Update TypeScript**

```ts
export interface WebhookEvent {
  id: string;
  type: string;
  schema_version: string;
  created_at: string;
  data: unknown;
  [k: string]: unknown;
}

const isV1 = (event: WebhookEvent, type: string): boolean =>
  event.schema_version === "1" && event.type === type;
```

Validate all five properties in `constructEvent`, preserve the parsed object and unknown fields, and make every stable guard call `isV1`.

- [ ] **Step 4: Update Python**

Make `WebhookEvent` and `WSEvent` core fields required, validate all five during parsing, preserve unknown data, and require version `"1"` in every stable guard.

- [ ] **Step 5: Verify and commit**

Run: `npm run build --workspace @e2a/sdk && npm test --workspace @e2a/sdk`

Run: `cd sdks/python && pytest tests/ -q && mypy src tests`

Expected: PASS.

```bash
git add sdks/typescript sdks/python
git commit -m "feat: freeze open SDK event envelope"
```

### Task 5: Freeze WebSocket close behavior across clients

**Files:**
- Create: `internal/ws/testdata/close-contract.json`
- Modify: `internal/ws/handler_test.go`
- Modify: `sdks/typescript/test/v1/ws.test.ts`
- Modify: `sdks/python/tests/test_v1_websocket.py`
- Modify: `cli/src/__tests__/listen.test.ts`

- [ ] **Step 1: Add a close-contract fixture**

Include 1000, both 1001 reason tokens, 1006, 1008, 1011, 4000/replaced, and an unknown 4xxx with `normal`, `transient`, `terminal`, or `replaced` classification.

- [ ] **Step 2: Drive server and client cases from the matrix**

Assert Go's stable reason tokens, TS/Python reconnect classification, CLI replacement explanation/permanent exit, and HTTP 401/403/404 handshake rejection before upgrade.

- [ ] **Step 3: Verify and commit**

Run: `go test ./internal/ws`

Run: `npm test --workspace @e2a/sdk -- --run ws`

Run: `cd sdks/python && pytest tests/test_v1_websocket.py -q`

Run: `npm test --workspace @e2a/cli -- --run listen`

Expected: PASS.

```bash
git add internal/ws sdks/typescript/test/v1/ws.test.ts sdks/python/tests/test_v1_websocket.py cli/src/__tests__/listen.test.ts
git commit -m "test: freeze websocket close contract"
```

### Task 6: Documentation, generation, and repository verification

**Files:**
- Modify: `docs/events.md`
- Modify: `docs/api.md`
- Modify: `docs/design/webhook-delivery-river-migration.md`
- Modify: `api/openapi.yaml`
- Modify: generated SDK artifacts if generation changes them

- [ ] **Step 1: Update public documentation**

Document `EventEnvelope` versus REST `EventJSON`, the stable mapping and beta inventory, open version handling, exact signing input, five required headers, 24-hour dual-sign grace, 300-second verifier tolerance, exact retry table, at-least-once deduplication, and the close matrix.

- [ ] **Step 2: Remove stale retry claims**

Replace every active “8 attempts over ~72h” or unused 24-hour delay claim with eight attempts spanning 29h21m. Mark historical design text superseded when it must remain.

- [ ] **Step 3: Regenerate and run contract gates**

Run: `make spec-check`

Run: `make generate-sdk-check`

Regenerate with the repository targets if either reports stale artifacts, inspect the diff, and rerun. Expected: PASS.

- [ ] **Step 4: Run focused and package gates**

Run: `go test ./internal/eventpayload ./internal/httpapi ./internal/webhook ./internal/webhookdelivery ./internal/ws`

Run: `npm run build --workspace @e2a/sdk`

Run: `npm test --workspace @e2a/sdk`

Run: `npm test --workspace @e2a/cli`

Run: `cd sdks/python && pytest tests/ -q && mypy src tests`

Expected: PASS.

- [ ] **Step 5: Run repository checks and inspect the diff**

Run: `make test-unit`

Run: `git diff origin/main...HEAD --check`

Run: `git diff origin/main...HEAD --stat`

Confirm no union/discriminator on `EventEnvelope`, no unmapped stable event, no closed SDK base type/version, and no stale retry timing.

- [ ] **Step 6: Commit**

```bash
git add api/openapi.yaml docs sdks
git commit -m "docs: freeze event and webhook contract"
```
