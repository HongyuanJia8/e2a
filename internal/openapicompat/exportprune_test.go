package openapicompat

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A miniature contract exercising every side of the exemption boundary:
//   - UserExport (envelope) → AgentIdentity (export-only interior),
//     Shared (also returned by a stable operation), and DocShared
//     (reachable only through a stable documentation component).
const pruneFixture = `
openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /v1/account/export:
    get:
      operationId: exportAccount
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/UserExport"
  /v1/things:
    get:
      operationId: listThings
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Shared"
  /v1/beta-things:
    get:
      operationId: betaThings
      x-stability-level: beta
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/BetaOnly"
components:
  schemas:
    UserExport:
      type: object
      additionalProperties: true
      required: [schema_version, agents]
      properties:
        schema_version: {type: string}
        agents:
          type: array
          items: {$ref: "#/components/schemas/AgentIdentity"}
        shared: {$ref: "#/components/schemas/Shared"}
        doc_shared: {$ref: "#/components/schemas/DocShared"}
    AgentIdentity:
      type: object
      additionalProperties: true
      required: [email]
      properties:
        email: {type: string}
        secret_internal: {type: string}
    Shared:
      type: object
      additionalProperties: true
      properties:
        name: {type: string}
    DocShared:
      type: object
      additionalProperties: true
      properties:
        size: {type: integer}
    EventPayloadDoc:
      type: object
      additionalProperties: true
      properties:
        attachment: {$ref: "#/components/schemas/DocShared"}
    BetaOnly:
      type: object
      additionalProperties: true
      x-stability-level: beta
      properties:
        experimental: {type: string}
`

func prune(t *testing.T, in string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := PruneExportInterior(strings.NewReader(in), &out); err != nil {
		t.Fatalf("PruneExportInterior: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal pruned YAML: %v", err)
	}
	return doc
}

func TestPruneExportInteriorCollapsesOnlyExportOnlySchemas(t *testing.T) {
	doc := prune(t, pruneFixture)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)

	// Export-only interior: collapsed to an open beta object.
	agent := schemas["AgentIdentity"].(map[string]any)
	if _, ok := agent["properties"]; ok {
		t.Error("AgentIdentity (export-only interior) must be collapsed — its properties are versioned by schema_version, not gated")
	}
	if got := agent["x-stability-level"]; got != "beta" {
		t.Errorf("collapsed interior must be stamped beta, got %v", got)
	}
	if got := agent["additionalProperties"]; got != true {
		t.Errorf("collapsed interior must stay an open object, got additionalProperties=%v", got)
	}

	// The envelope itself stays fully gated.
	envelope := schemas["UserExport"].(map[string]any)
	props, _ := envelope["properties"].(map[string]any)
	if _, ok := props["schema_version"]; !ok {
		t.Error("UserExport envelope must keep its properties (schema_version stays gated)")
	}
	if _, ok := envelope["x-stability-level"]; ok {
		t.Error("UserExport envelope must not be marked beta by the prune")
	}

	// Schemas the stable surface reaches on its own stay fully gated.
	for _, name := range []string{"Shared", "DocShared"} {
		sc := schemas[name].(map[string]any)
		if _, ok := sc["properties"]; !ok {
			t.Errorf("%s is shared with the stable surface and must NOT be collapsed", name)
		}
	}

	// Untouched bystanders.
	if _, ok := schemas["EventPayloadDoc"].(map[string]any)["properties"]; !ok {
		t.Error("stable documentation component must not be collapsed")
	}
	if _, ok := schemas["BetaOnly"].(map[string]any)["properties"]; !ok {
		t.Error("beta-operation schema outside the export is not this prune's business")
	}
}

// The prune's whole purpose: two documents whose export interiors differ must
// prune to semantically identical schemas, while an envelope change must
// survive the prune (so oasdiff still gates it).
func TestPruneExportInteriorMakesInteriorChangesInvisible(t *testing.T) {
	changed := strings.Replace(pruneFixture, "secret_internal: {type: string}", "renamed_field: {type: integer}", 1)
	if changed == pruneFixture {
		t.Fatal("fixture edit did not apply")
	}
	a := prune(t, pruneFixture)["components"].(map[string]any)["schemas"].(map[string]any)["AgentIdentity"]
	b := prune(t, changed)["components"].(map[string]any)["schemas"].(map[string]any)["AgentIdentity"]
	ay, _ := yaml.Marshal(a)
	by, _ := yaml.Marshal(b)
	if string(ay) != string(by) {
		t.Errorf("interior change must be invisible after pruning:\n%s\nvs\n%s", ay, by)
	}

	dropped := strings.Replace(pruneFixture, "schema_version: {type: string}", "", 1)
	env := prune(t, dropped)["components"].(map[string]any)["schemas"].(map[string]any)["UserExport"].(map[string]any)
	props, _ := env["properties"].(map[string]any)
	if _, ok := props["schema_version"]; ok {
		t.Fatal("fixture edit did not apply")
	}
	// The point: the pruned document still differs from the unmodified one at
	// the envelope, so oasdiff sees the removal.
	orig := prune(t, pruneFixture)["components"].(map[string]any)["schemas"].(map[string]any)["UserExport"]
	oy, _ := yaml.Marshal(orig)
	ey, _ := yaml.Marshal(env)
	if string(oy) == string(ey) {
		t.Error("an envelope change must survive the prune so the gate can reject it")
	}
}

func TestPruneExportInteriorNoEnvelopeIsANoOp(t *testing.T) {
	in := `
openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /v1/things:
    get:
      operationId: listThings
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Shared"
components:
  schemas:
    Shared:
      type: object
      properties:
        name: {type: string}
`
	doc := prune(t, in)
	sc := doc["components"].(map[string]any)["schemas"].(map[string]any)["Shared"].(map[string]any)
	if _, ok := sc["properties"]; !ok {
		t.Error("document without a UserExport envelope must pass through unchanged")
	}
}
