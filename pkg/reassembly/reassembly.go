package reassembly

import (
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"strings"

	"github.com/bonjoski/shield/pkg/shield"
)

var (
	ErrSyntaxValidation = errors.New("reassembly: generated code contains syntax errors")
	ErrUnmappedToken    = errors.New("reassembly: unmapped placeholder token encountered in AI response")
)

type Reassembler struct{}

func NewReassembler() *Reassembler {
	return &Reassembler{}
}

// CheckUnmappedPlaceholders inspects the AI response text to verify that no fabricated
// or desynchronized "[SECRET_REF_...]" strings were invented by the model.
func (r *Reassembler) CheckUnmappedPlaceholders(aiResponse string, tm *shield.TokenMap) error {
	if tm == nil {
		return nil
	}

	knownRefs := make(map[string]bool)
	for _, ref := range tm.References() {
		knownRefs[ref] = true
	}

	startIdx := 0
	for {
		idx := strings.Index(aiResponse[startIdx:], "[SECRET_REF_")
		if idx == -1 {
			break
		}
		actualIdx := startIdx + idx
		endIdx := strings.Index(aiResponse[actualIdx:], "]")
		if endIdx == -1 {
			break
		}
		ref := aiResponse[actualIdx : actualIdx+endIdx+1]
		if !knownRefs[ref] {
			return fmt.Errorf("%w: unknown token '%s'", ErrUnmappedToken, ref)
		}
		startIdx = actualIdx + endIdx + 1
	}

	return nil
}

// ValidateSyntax performs syntactic verification on generated code snippets before
// applying patches to the local filesystem.
func (r *Reassembler) ValidateSyntax(lang string, code string) error {
	switch strings.ToLower(lang) {
	case "go", "golang":
		fset := token.NewFileSet()
		// Wrap snippet in package main if not present to enable parsing
		src := code
		if !strings.Contains(src, "package ") {
			src = fmt.Sprintf("package main\n\nfunc main() {\n%s\n}", src)
		}
		_, err := parser.ParseFile(fset, "generated.go", src, parser.AllErrors)
		if err != nil {
			return fmt.Errorf("%w: Go parse error: %v", ErrSyntaxValidation, err)
		}
	}
	return nil
}
