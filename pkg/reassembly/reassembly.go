package reassembly

import (
	"errors"
	"fmt"
	"go/parser"
	"go/scanner"
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

// firstGoToken scans src using go/scanner and returns the first non-comment token
// along with whether any lexical scanner errors occurred.
func firstGoToken(src string) (token.Token, error) {
	fset := token.NewFileSet()
	file := fset.AddFile("snippet.go", fset.Base(), len(src))
	var scanErr error
	var s scanner.Scanner
	s.Init(file, []byte(src), func(_ token.Position, msg string) {
		if scanErr == nil {
			scanErr = errors.New(msg)
		}
	}, 0)

	_, tok, _ := s.Scan()
	if scanErr != nil {
		return token.ILLEGAL, scanErr
	}
	return tok, nil
}

// ValidateSyntax performs syntactic verification on generated code snippets before
// applying patches to the local filesystem.
func (r *Reassembler) ValidateSyntax(lang string, code string) error {
	switch strings.ToLower(lang) {
	case "go", "golang":
		if strings.TrimSpace(code) == "" {
			return fmt.Errorf("%w: empty Go snippet", ErrSyntaxValidation)
		}

		firstTok, lexErr := firstGoToken(code)
		if lexErr != nil {
			return fmt.Errorf("%w: Go lexical error: %w", ErrSyntaxValidation, lexErr)
		}

		// Case 1: Full Go source file starting with a real `package` token
		if firstTok == token.PACKAGE {
			fset := token.NewFileSet()
			if _, err := parser.ParseFile(fset, "generated.go", code, parser.AllErrors); err != nil {
				return fmt.Errorf("%w: Go parse error: %w", ErrSyntaxValidation, err)
			}
			return nil
		}

		// Case 2: Top-level declarations without `package` header (e.g. `import ...`, `func helper() {}`)
		declWrapped := "package main\n\n" + code
		fsetDecl := token.NewFileSet()
		if _, err := parser.ParseFile(fsetDecl, "generated_decl.go", declWrapped, parser.AllErrors); err == nil {
			return nil
		}

		// Case 3: Statement/expression block (even if a string literal inside contains "package ")
		stmtWrapped := "package main\n\nfunc _() {\n" + code + "\n}\n"
		fsetStmt := token.NewFileSet()
		parsed, err := parser.ParseFile(fsetStmt, "generated_stmt.go", stmtWrapped, parser.AllErrors)
		if err != nil {
			return fmt.Errorf("%w: Go parse error: %w", ErrSyntaxValidation, err)
		}
		// Reject brace-breakout attempts that escape `func _() { ... }` into extra declarations.
		if len(parsed.Decls) != 1 {
			return fmt.Errorf("%w: statement snippet broke out of enclosing function scope", ErrSyntaxValidation)
		}
	}
	return nil
}
