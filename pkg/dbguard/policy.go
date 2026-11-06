package dbguard

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	
	
)

// ActionType represents the policy verdict action.
type ActionType string

const (
	ActionPass    ActionType = "PASS"
	ActionRewrite ActionType = "REWRITE"
	ActionBlock   ActionType = "BLOCK"
)

// FilterVerdict contains the security decision for an intercepted query.
type FilterVerdict struct {
	Action       ActionType
	RewrittenSQL string
	Reason       string
	EntropyLimit float64
}

// QueryFilter defines the interface for evaluating and transforming queries.
type QueryFilter interface {
	InspectQuery(ctx context.Context, token string, sql string) (*FilterVerdict, error)
}

// TokenVerifier defines the interface for authenticating Conjoiner task tokens.
type TokenVerifier interface {
	VerifyToken(ctx context.Context, token string) error
}

// DefaultTokenVerifier is a default implementation of TokenVerifier.
type DefaultTokenVerifier struct {
	AllowedTokens map[string]bool
	AllowAnyValid bool
}

// NewDefaultTokenVerifier returns a TokenVerifier that accepts non-empty tokens if allowAny is true,
// or only tokens present in allowedTokens.
func NewDefaultTokenVerifier(allowAny bool, allowedTokens ...string) *DefaultTokenVerifier {
	m := make(map[string]bool)
	for _, tok := range allowedTokens {
		m[tok] = true
	}
	return &DefaultTokenVerifier{
		AllowedTokens: m,
		AllowAnyValid: allowAny,
	}
}

// VerifyToken checks whether the token is valid.
func (v *DefaultTokenVerifier) VerifyToken(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("missing conjoiner task token")
	}
	if v.AllowAnyValid {
		return nil
	}
	if !v.AllowedTokens[token] {
		return fmt.Errorf("unrecognized or expired conjoiner token %q", token)
	}
	return nil
}

// Policy specifies database firewall protection rules.
type Policy struct {
	BlockDDL                    bool
	BlockUnconstrainedMutations bool
	BlockPrivilegeEscalation    bool
	EnforceRowLimit             int64
	RequireConjoinerToken       bool
	EntropyLimit                float64
}

// DefaultPolicy returns secure defaults for Crucible.
func DefaultPolicy() Policy {
	return Policy{
		BlockDDL:                    true,
		BlockUnconstrainedMutations: true,
		BlockPrivilegeEscalation:    true,
		EnforceRowLimit:             100,
		RequireConjoinerToken:       false,
		EntropyLimit:                DefaultThreshold,
	}
}

// Engine implements QueryFilter evaluating queries against Policy and TokenVerifier.
type Engine struct {
	policy   Policy
	verifier TokenVerifier
}

// NewEngine creates a new policy evaluation Engine.
func NewEngine(p Policy, verifier TokenVerifier) *Engine {
	if verifier == nil {
		verifier = NewDefaultTokenVerifier(true)
	}
	if p.EntropyLimit <= 0 {
		p.EntropyLimit = DefaultThreshold
	}
	return &Engine{
		policy:   p,
		verifier: verifier,
	}
}

// Regex for extracting Conjoiner tokens from SQL comments:
// /* conjoiner:<token> */ or -- conjoiner:<token>
var (
	cStyleCommentRegex = regexp.MustCompile(`/\*\s*conjoiner:([^\s*]+)\s*\*/`)
	lineCommentRegex   = regexp.MustCompile(`--\s*conjoiner:([^\r\n\s]+)`)
)

// ExtractTokenFromSQL searches for Conjoiner task tokens embedded in SQL comments.
func ExtractTokenFromSQL(sql string) (token string, cleanSQL string) {
	if match := cStyleCommentRegex.FindStringSubmatch(sql); len(match) > 1 {
		token = strings.TrimSpace(match[1])
		cleanSQL = cStyleCommentRegex.ReplaceAllString(sql, "")
		return token, cleanSQL
	}
	if match := lineCommentRegex.FindStringSubmatch(sql); len(match) > 1 {
		token = strings.TrimSpace(match[1])
		cleanSQL = lineCommentRegex.ReplaceAllString(sql, "")
		return token, cleanSQL
	}
	return "", sql
}

// InspectQuery evaluates an SQL statement against policy rules and tokens.
func (e *Engine) InspectQuery(ctx context.Context, sessionToken string, sql string) (*FilterVerdict, error) {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" || trimmed == ";" {
		return &FilterVerdict{
			Action:       ActionPass,
			RewrittenSQL: sql,
			EntropyLimit: e.policy.EntropyLimit,
		}, nil
	}

	// 1. Check for token in SQL comment preface if sessionToken was not provided
	extractedToken, _ := ExtractTokenFromSQL(sql)
	effectiveToken := sessionToken
	if effectiveToken == "" {
		effectiveToken = extractedToken
	}

	// 2. Enforce Conjoiner token requirement
	if e.policy.RequireConjoinerToken {
		if err := e.verifier.VerifyToken(ctx, effectiveToken); err != nil {
			return &FilterVerdict{
				Action:       ActionBlock,
				Reason:       fmt.Sprintf("Conjoiner token validation failed: %v", err),
				EntropyLimit: e.policy.EntropyLimit,
			}, nil
		}
	}

	// 3. Parse AST
	tree, err := Parse(sql)
	if err != nil {
		return &FilterVerdict{
			Action:       ActionBlock,
			Reason:       fmt.Sprintf("SQL parse error: %v", err),
			EntropyLimit: e.policy.EntropyLimit,
		}, nil
	}

	// 4. Inspect AST nodes
	inspection, err := Inspect(tree)
	if err != nil {
		return &FilterVerdict{
			Action:       ActionBlock,
			Reason:       fmt.Sprintf("SQL inspection error: %v", err),
			EntropyLimit: e.policy.EntropyLimit,
		}, nil
	}

	// Check DDL
	if e.policy.BlockDDL && inspection.HasDDL {
		return &FilterVerdict{
			Action:       ActionBlock,
			Reason:       fmt.Sprintf("DDL statement '%s' blocked by agent security policy", inspection.DDLType),
			EntropyLimit: e.policy.EntropyLimit,
		}, nil
	}

	// Check Privilege Escalation
	if e.policy.BlockPrivilegeEscalation && inspection.HasPrivilegeEscalation {
		return &FilterVerdict{
			Action:       ActionBlock,
			Reason:       fmt.Sprintf("Privilege escalation statement '%s' blocked by agent security policy", inspection.PrivilegeType),
			EntropyLimit: e.policy.EntropyLimit,
		}, nil
	}

	// Check Unconstrained Mutations
	if e.policy.BlockUnconstrainedMutations && inspection.HasUnconstrainedMutation {
		return &FilterVerdict{
			Action:       ActionBlock,
			Reason:       fmt.Sprintf("Unconstrained mutation '%s' blocked by agent security policy", inspection.UnconstrainedMutationType),
			EntropyLimit: e.policy.EntropyLimit,
		}, nil
	}

	// 5. Enforce Row Limit
	if e.policy.EnforceRowLimit > 0 && inspection.HasSelect {
		rewritten, modified, err := EnforceLimit(tree, e.policy.EnforceRowLimit)
		if err != nil {
			return &FilterVerdict{
				Action:       ActionBlock,
				Reason:       fmt.Sprintf("Failed to rewrite query limit: %v", err),
				EntropyLimit: e.policy.EntropyLimit,
			}, nil
		}
		if modified {
			return &FilterVerdict{
				Action:       ActionRewrite,
				RewrittenSQL: rewritten,
				Reason:       fmt.Sprintf("Injected LIMIT %d on unbounded query", e.policy.EnforceRowLimit),
				EntropyLimit: e.policy.EntropyLimit,
			}, nil
		}
	}

	return &FilterVerdict{
		Action:       ActionPass,
		RewrittenSQL: sql,
		EntropyLimit: e.policy.EntropyLimit,
	}, nil
}
