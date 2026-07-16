package openapicompat

import (
	"fmt"
	"io"
	"reflect"

	"gopkg.in/yaml.v3"
)

// CheckSecuritySchemes rejects any semantic change to the authentication
// scheme definitions. oasdiff detects scheme additions/removals but does not
// currently detect fields such as HTTP scheme or API-key name/location.
func CheckSecuritySchemes(base, revision io.Reader) error {
	baseSchemes, err := readSecuritySchemes(base)
	if err != nil {
		return fmt.Errorf("decode base security schemes: %w", err)
	}
	revisionSchemes, err := readSecuritySchemes(revision)
	if err != nil {
		return fmt.Errorf("decode revision security schemes: %w", err)
	}
	if !reflect.DeepEqual(baseSchemes, revisionSchemes) {
		return fmt.Errorf("[security-schemes-changed] components.securitySchemes changed; authentication contract changes require an API-version review")
	}
	return nil
}

func readSecuritySchemes(r io.Reader) (any, error) {
	var doc map[string]any
	if err := yaml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}
	components, _ := doc["components"].(map[string]any)
	return components["securitySchemes"], nil
}
