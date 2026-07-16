// Package openapicompat contains normalization used only by the OpenAPI
// compatibility gate. It does not alter runtime request or response behavior.
package openapicompat

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

const (
	e2aStabilityExtension = "x-stability"
	oasdiffExtension      = "x-stability-level"
)

// NormalizeStability mirrors e2a's historical experimental marker into the
// lifecycle extension understood by oasdiff. Older release specs can therefore
// be compared with newer specs without misclassifying beta APIs as stable.
func NormalizeStability(r io.Reader, w io.Writer) error {
	var doc yaml.Node
	if err := yaml.NewDecoder(r).Decode(&doc); err != nil {
		return fmt.Errorf("decode OpenAPI YAML: %w", err)
	}
	if err := normalizeNode(&doc); err != nil {
		return err
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer enc.Close()
	if err := enc.Encode(&doc); err != nil {
		return fmt.Errorf("encode normalized OpenAPI YAML: %w", err)
	}
	return nil
}

func normalizeNode(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		var e2aStability, oasdiffStability *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			switch node.Content[i].Value {
			case e2aStabilityExtension:
				e2aStability = node.Content[i+1]
			case oasdiffExtension:
				oasdiffStability = node.Content[i+1]
			}
		}
		if e2aStability != nil && e2aStability.Value == "experimental" {
			switch {
			case oasdiffStability == nil:
				node.Content = append(node.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: oasdiffExtension},
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "beta"},
				)
			case oasdiffStability.Value != "beta":
				return fmt.Errorf("conflicting stability markers at line %d: %s=experimental but %s=%s",
					e2aStability.Line, e2aStabilityExtension, oasdiffExtension, oasdiffStability.Value)
			}
		}
	}
	for _, child := range node.Content {
		if err := normalizeNode(child); err != nil {
			return err
		}
	}
	return nil
}
