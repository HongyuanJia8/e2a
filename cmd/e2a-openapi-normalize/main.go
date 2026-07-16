// e2a-openapi-normalize prepares old and new e2a OpenAPI documents for
// semantic comparison. It is an internal build tool, not a shipped command.
package main

import (
	"fmt"
	"os"

	"github.com/tokencanopy/e2a/internal/openapicompat"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <input.yaml> <output.yaml>\n", os.Args[0])
		os.Exit(2)
	}
	in, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open input: %v\n", err)
		os.Exit(1)
	}
	defer in.Close()
	out, err := os.Create(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "create output: %v\n", err)
		os.Exit(1)
	}
	if err := openapicompat.NormalizeStability(in, out); err != nil {
		out.Close()
		fmt.Fprintf(os.Stderr, "normalize OpenAPI: %v\n", err)
		os.Exit(1)
	}
	if err := out.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close output: %v\n", err)
		os.Exit(1)
	}
}
