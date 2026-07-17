package openapicompat

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// The account export's versioned-interior exemption, gate side.
//
// GET /v1/account/export (operation exportAccount) is a STABLE operation
// whose top-level UserExport envelope (the top-level keys and schema_version)
// is frozen with the GA surface. Its INTERIOR record schemas are snapshots of
// internal storage models, versioned by UserExport.schema_version instead of
// the v1 freeze (they carry `x-stability-level: beta` in the emitted spec —
// see internal/httpapi/stability.go). oasdiff, however, only honors
// stability levels at the OPERATION level, so without help the gate would
// block every interior change (and the marker introduction itself) as a
// breaking change on the stable export operation.
//
// PruneExportInterior therefore collapses the interior for gate comparison
// only: every component schema reachable from UserExport — EXCEPT the
// envelope itself and any schema the stable surface reaches on its own (via
// another stable operation, or via a stable operation-unreachable
// documentation component such as the event payloads) — is replaced by an
// open object stamped beta. Applied to BOTH sides of the comparison, the
// interiors always compare equal, while the envelope, the operation, and
// every shared schema remain fully gated. The boundary is COMPUTED by
// reachability (the same rule the server uses to stamp the markers), never
// read from the markers themselves, so it holds for historical base
// documents that predate the markers and cannot be widened by hand-marking a
// stable schema beta.
const (
	exportOperationID    = "exportAccount"
	exportEnvelopeSchema = "UserExport"
)

// PruneExportInterior rewrites an OpenAPI document for the compatibility
// gate: the account export's versioned-interior schemas are collapsed to
// `{type: object, additionalProperties: true, x-stability-level: beta}`.
// A document with no UserExport component passes through semantically
// unchanged. Like NormalizeStability, this never alters runtime behavior —
// it only feeds oasdiff.
func PruneExportInterior(r io.Reader, w io.Writer) error {
	var doc map[string]any
	if err := yaml.NewDecoder(r).Decode(&doc); err != nil {
		return fmt.Errorf("decode OpenAPI YAML: %w", err)
	}
	if err := pruneExportInterior(doc); err != nil {
		return err
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer enc.Close()
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode pruned OpenAPI YAML: %w", err)
	}
	return nil
}

func pruneExportInterior(doc map[string]any) error {
	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	if _, ok := schemas[exportEnvelopeSchema]; !ok {
		return nil // document predates (or lacks) the export envelope
	}

	exportSet, err := schemaClosure(schemas, map[string]bool{exportEnvelopeSchema: true})
	if err != nil {
		return err
	}

	// Stable surface that must stay fully gated: everything reachable from an
	// operation other than the export that is not beta, plus everything
	// reachable from a stable operation-unreachable documentation component
	// (event payload schemas etc.).
	allOpRoots := map[string]bool{}
	stableOtherRoots := map[string]bool{}
	paths, _ := doc["paths"].(map[string]any)
	for _, rawItem := range paths {
		item, _ := rawItem.(map[string]any)
		for _, rawOp := range item {
			op, ok := rawOp.(map[string]any)
			if !ok {
				continue
			}
			id, _ := op["operationId"].(string)
			if id == "" {
				continue
			}
			roots := map[string]bool{}
			collectSchemaRefs(op["requestBody"], roots)
			collectSchemaRefs(op["responses"], roots)
			isBeta := op[oasdiffExtension] == "beta" || op[e2aStabilityExtension] == "experimental"
			for name := range roots {
				allOpRoots[name] = true
				if id != exportOperationID && !isBeta {
					stableOtherRoots[name] = true
				}
			}
		}
	}
	opReachable, err := schemaClosure(schemas, allOpRoots)
	if err != nil {
		return err
	}
	stableSurface, err := schemaClosure(schemas, stableOtherRoots)
	if err != nil {
		return err
	}
	docRoots := map[string]bool{}
	for name, raw := range schemas {
		sc, _ := raw.(map[string]any)
		if opReachable[name] || exportSet[name] {
			continue
		}
		if sc[oasdiffExtension] == "beta" || sc[e2aStabilityExtension] == "experimental" {
			continue
		}
		docRoots[name] = true
	}
	docReachable, err := schemaClosure(schemas, docRoots)
	if err != nil {
		return err
	}
	for name := range docReachable {
		stableSurface[name] = true
	}

	for name := range exportSet {
		if name == exportEnvelopeSchema || stableSurface[name] {
			continue
		}
		schemas[name] = map[string]any{
			"type":                 "object",
			"additionalProperties": true,
			oasdiffExtension:       "beta",
			"description": "Interior record shape of the account export, collapsed for compatibility " +
				"comparison: it is versioned by UserExport.schema_version, not by the v1 freeze.",
		}
	}
	return nil
}

// collectSchemaRefs records every component-schema name referenced anywhere
// under a generic YAML node.
func collectSchemaRefs(node any, out map[string]bool) {
	switch n := node.(type) {
	case map[string]any:
		if ref, ok := n["$ref"].(string); ok {
			const prefix = "#/components/schemas/"
			if len(ref) > len(prefix) && ref[:len(prefix)] == prefix {
				out[ref[len(prefix):]] = true
			}
		}
		for _, v := range n {
			collectSchemaRefs(v, out)
		}
	case []any:
		for _, v := range n {
			collectSchemaRefs(v, out)
		}
	}
}

// schemaClosure expands root component names to everything transitively
// referenced through components.schemas.
func schemaClosure(schemas map[string]any, roots map[string]bool) (map[string]bool, error) {
	seen := map[string]bool{}
	stack := make([]string, 0, len(roots))
	for name := range roots {
		stack = append(stack, name)
	}
	for len(stack) > 0 {
		name := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[name] {
			continue
		}
		seen[name] = true
		sc, ok := schemas[name]
		if !ok {
			return nil, fmt.Errorf("schema %q is referenced but not defined in components.schemas", name)
		}
		next := map[string]bool{}
		collectSchemaRefs(sc, next)
		for n := range next {
			if !seen[n] {
				stack = append(stack, n)
			}
		}
	}
	return seen, nil
}
