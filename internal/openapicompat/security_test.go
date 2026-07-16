package openapicompat

import (
	"strings"
	"testing"
)

const bearerSecurity = `
openapi: 3.1.0
components:
  securitySchemes:
    bearer:
      type: http
      scheme: bearer
      bearerFormat: API key
`

func TestCheckSecuritySchemesAcceptsEquivalentDocuments(t *testing.T) {
	reordered := `
components:
  securitySchemes:
    bearer:
      bearerFormat: API key
      scheme: bearer
      type: http
openapi: 3.1.0
`
	if err := CheckSecuritySchemes(strings.NewReader(bearerSecurity), strings.NewReader(reordered)); err != nil {
		t.Fatalf("CheckSecuritySchemes: %v", err)
	}
}

func TestCheckSecuritySchemesRejectsHTTPMechanismChange(t *testing.T) {
	revision := strings.Replace(bearerSecurity, "scheme: bearer", "scheme: basic", 1)
	err := CheckSecuritySchemes(strings.NewReader(bearerSecurity), strings.NewReader(revision))
	if err == nil || !strings.Contains(err.Error(), "security-schemes-changed") {
		t.Fatalf("error = %v, want security-schemes-changed", err)
	}
}

func TestCheckSecuritySchemesRejectsAPIKeyLocationChange(t *testing.T) {
	base := `
openapi: 3.1.0
components:
  securitySchemes:
    key:
      type: apiKey
      in: header
      name: Authorization
`
	revision := strings.Replace(base, "in: header", "in: query", 1)
	err := CheckSecuritySchemes(strings.NewReader(base), strings.NewReader(revision))
	if err == nil || !strings.Contains(err.Error(), "security-schemes-changed") {
		t.Fatalf("error = %v, want security-schemes-changed", err)
	}
}
