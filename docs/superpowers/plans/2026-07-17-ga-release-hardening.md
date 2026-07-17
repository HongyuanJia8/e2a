# GA Release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the final v1 GA release-control and HTTP connection-hardening gaps found in the launch audit.

**Architecture:** Keep the changes narrow and mechanically enforced. The OpenAPI compatibility harness owns the freeze rule, npm's root lockfile owns deterministic workspace dependency resolution, and a small HTTP-server constructor owns safe connection defaults without changing WebSocket or request-body semantics.

**Tech Stack:** Bash/oasdiff fixtures, npm workspaces and GitHub Actions, Go `net/http`, Markdown release documentation.

---

### Task 1: Freeze first-time request bounds

**Files:**
- Modify: `scripts/test-openapi-compat.sh`
- Create: `api/testdata/oasdiff/request-property-max-length-set.yaml`
- Modify: `api/oasdiff-levels.txt`
- Modify: `docs/api-compatibility-gate.md`

- [ ] Add a fixture that differs from `base.yaml` only by adding `maxLength: 200` to `StableRequest.name`.
- [ ] Add `expect_fail "new request maxLength" ... "request-property-max-length-set"` to the compatibility harness.
- [ ] Run `make openapi-compat-test`; verify it fails because the current severity override is informational.
- [ ] Remove `request-property-max-length-set info` and rewrite the policy as the active GA rule.
- [ ] Re-run `make openapi-compat-test`; verify every compatibility fixture passes.

### Task 2: Restore deterministic workspace installs

**Files:**
- Regenerate: `package-lock.json`
- Modify: `.github/workflows/test.yml`
- Modify: `.github/workflows/publish-cli.yml`
- Modify: `.github/workflows/publish-ts-sdk.yml`
- Modify: `CLAUDE.md`
- Create: `scripts/check-repository-text-integrity.sh`

- [ ] Add a repository integrity script that rejects merge-conflict markers and parses both npm lockfiles as JSON.
- [ ] Run it and verify it fails on the committed root lockfile.
- [ ] Regenerate the root lockfile from checked-in manifests with `npm install --package-lock-only --ignore-scripts`.
- [ ] Replace every root workspace `npm install --package-lock=false` with `npm ci`; keep the web workspace on its own valid lockfile.
- [ ] Add the integrity script as an early CI job and update contributor commands to use `npm ci`.
- [ ] Run the integrity script and `npm ci`; verify deterministic installation succeeds.

### Task 3: Add safe HTTP server defaults

**Files:**
- Create: `cmd/e2a/http_server.go`
- Create: `cmd/e2a/http_server_test.go`
- Modify: `cmd/e2a/main.go`

- [ ] Write a test requiring `ReadHeaderTimeout == 10s`, `IdleTimeout == 120s`, and zero whole-request read/write timeouts.
- [ ] Run the focused test and verify it fails because the constructor does not exist.
- [ ] Add `newHTTPServer(addr, handler)` with exactly those defaults and use it from `main.go`.
- [ ] Run `go test -count=1 ./cmd/e2a` and verify it passes.

### Task 4: Establish the API GA baseline

**Files:**
- Modify: `docs/api-compatibility-gate.md`
- Modify: `README.md`
- Modify: `SECURITY.md`

- [ ] State that the stable `/v1` baseline begins at the GA freeze introduced by `5f58956b` and its eventual GA release tag.
- [ ] Clarify that earlier `v1.0.x` application/cherry-pick tags do not establish `/v1` API compatibility.
- [ ] Remove contradictory pre-GA/current-GA wording and make launch status consistent.
- [ ] Run targeted text searches to ensure no contradictory GA statements remain.

### Task 5: Full verification and review

**Files:** all files above.

- [ ] Run `make spec-check` and `make openapi-compat-test`.
- [ ] Run `go test -count=1 ./cmd/e2a ./internal/httpapi` and `go build ./cmd/e2a`.
- [ ] Run `npm ci`, workspace builds/tests, and repository integrity checks.
- [ ] Run Python SDK tests.
- [ ] Review the final diff against the audit findings and confirm no unrelated changes were introduced.
