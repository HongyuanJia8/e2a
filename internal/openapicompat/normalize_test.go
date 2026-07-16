package openapicompat

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNormalizeStabilityAddsOASDiffMirrorRecursively(t *testing.T) {
	in := `
openapi: 3.1.0
paths:
  /beta:
    get:
      x-stability: experimental
      responses: {}
components:
  schemas:
    Beta:
      type: object
      x-stability: experimental
      properties:
        field:
          type: string
          x-stability: experimental
    Stable:
      type: object
`
	var out bytes.Buffer
	if err := NormalizeStability(strings.NewReader(in), &out); err != nil {
		t.Fatalf("NormalizeStability: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal normalized YAML: %v", err)
	}
	paths := doc["paths"].(map[string]any)
	operation := paths["/beta"].(map[string]any)["get"].(map[string]any)
	if got := operation["x-stability-level"]; got != "beta" {
		t.Fatalf("operation x-stability-level = %v, want beta", got)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	beta := schemas["Beta"].(map[string]any)
	if got := beta["x-stability-level"]; got != "beta" {
		t.Fatalf("schema x-stability-level = %v, want beta", got)
	}
	field := beta["properties"].(map[string]any)["field"].(map[string]any)
	if got := field["x-stability-level"]; got != "beta" {
		t.Fatalf("property x-stability-level = %v, want beta", got)
	}
	if _, ok := schemas["Stable"].(map[string]any)["x-stability-level"]; ok {
		t.Fatal("stable schema unexpectedly gained x-stability-level")
	}
}

func TestNormalizeStabilityRejectsConflictingMarkers(t *testing.T) {
	in := `
openapi: 3.1.0
paths:
  /conflict:
    get:
      x-stability: experimental
      x-stability-level: stable
      responses: {}
`
	var out bytes.Buffer
	err := NormalizeStability(strings.NewReader(in), &out)
	if err == nil || !strings.Contains(err.Error(), "conflicting stability markers") {
		t.Fatalf("error = %v, want conflicting stability markers", err)
	}
}
