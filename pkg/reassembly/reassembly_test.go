package reassembly

import (
	"testing"

	"github.com/bonjoski/shield/pkg/shield"
)

func TestReassemblerUnmappedTokens(t *testing.T) {
	r := NewReassembler()
	tm := shield.NewTokenMap()
	knownRef := tm.Add("mysecret", "MY_KEY")

	validResp := "Here is your refactored code with " + knownRef
	if err := r.CheckUnmappedPlaceholders(validResp, tm); err != nil {
		t.Fatalf("expected valid response to pass, got: %v", err)
	}

	invalidResp := "Here is a fabricated token: [SECRET_REF_deadbeef12345678]"
	if err := r.CheckUnmappedPlaceholders(invalidResp, tm); err == nil {
		t.Fatalf("expected error on unmapped placeholder token")
	}
}

func TestReassemblerSyntaxValidation(t *testing.T) {
	r := NewReassembler()

	validGo := `
package main

import "fmt"

func main() {
    fmt.Println("Hello world")
}
`
	if err := r.ValidateSyntax("go", validGo); err != nil {
		t.Fatalf("expected valid Go code to pass syntax check, got: %v", err)
	}

	invalidGo := `
package main
func main() {
    fmt.Println("Missing closing brace"
`
	if err := r.ValidateSyntax("go", invalidGo); err == nil {
		t.Fatalf("expected invalid Go code to fail syntax check")
	}
}
