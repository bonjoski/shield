package dbguard

import (
	"context"
	"strings"
	"testing"
)

func TestPolicyEngineAllowedQueries(t *testing.T) {
	engine := NewEngine(DefaultPolicy(), nil)
	ctx := context.Background()

	safeQueries := []string{
		"SELECT id, username FROM users WHERE id = 1;",
		"SELECT count(*) FROM orders WHERE status = 'shipped';",
		"INSERT INTO logs (level, message) VALUES ('info', 'test message');",
		"UPDATE users SET email = 'alice@example.com' WHERE id = 10;",
		"DELETE FROM session_tokens WHERE expires_at < NOW();",
	}

	for _, sql := range safeQueries {
		verdict, err := engine.InspectQuery(ctx, "test_token", sql)
		if err != nil {
			t.Fatalf("Unexpected error for %q: %v", sql, err)
		}
		if verdict.Action == ActionBlock {
			t.Errorf("Expected query to pass, but got ActionBlock: %q (reason: %s)", sql, verdict.Reason)
		}
	}
}

func TestPolicyEngineBlockedDDL(t *testing.T) {
	engine := NewEngine(DefaultPolicy(), nil)
	ctx := context.Background()

	ddlQueries := []string{
		"DROP TABLE users;",
		"DROP DATABASE prod;",
		"ALTER TABLE users DROP COLUMN password;",
		"TRUNCATE payments;",
		"GRANT ALL PRIVILEGES ON DATABASE app TO evil_agent;",
		"CREATE ROLE attacker WITH SUPERUSER;",
	}

	for _, sql := range ddlQueries {
		verdict, err := engine.InspectQuery(ctx, "test_token", sql)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if verdict.Action != ActionBlock {
			t.Errorf("Expected ActionBlock for %q, got %s", sql, verdict.Action)
		}
		if !strings.Contains(verdict.Reason, "blocked") {
			t.Errorf("Expected blocked reason for %q, got %s", sql, verdict.Reason)
		}
	}
}

func TestPolicyEngineUnconstrainedMutations(t *testing.T) {
	engine := NewEngine(DefaultPolicy(), nil)
	ctx := context.Background()

	mutations := []string{
		"UPDATE users SET role = 'admin';",
		"DELETE FROM users;",
		"DELETE FROM payments;",
	}

	for _, sql := range mutations {
		verdict, err := engine.InspectQuery(ctx, "test_token", sql)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if verdict.Action != ActionBlock {
			t.Errorf("Expected ActionBlock for unconstrained mutation %q, got %s", sql, verdict.Action)
		}
	}
}

func TestPolicyEngineLimitInjection(t *testing.T) {
	engine := NewEngine(DefaultPolicy(), nil)
	ctx := context.Background()

	sql := "SELECT * FROM users;"
	verdict, err := engine.InspectQuery(ctx, "test_token", sql)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if verdict.Action != ActionRewrite {
		t.Fatalf("Expected ActionRewrite, got %s", verdict.Action)
	}
	if !strings.Contains(verdict.RewrittenSQL, "LIMIT 100") {
		t.Fatalf("Expected LIMIT 100 in rewritten SQL, got: %s", verdict.RewrittenSQL)
	}
}

func TestConjoinerTokenExtractionAndVerification(t *testing.T) {
	verifier := NewDefaultTokenVerifier(false, "conjoiner_valid_token_123")
	pol := DefaultPolicy()
	pol.RequireConjoinerToken = true
	engine := NewEngine(pol, verifier)
	ctx := context.Background()

	// 1. Missing token -> should block
	verdict, _ := engine.InspectQuery(ctx, "", "SELECT id FROM users WHERE id = 1;")
	if verdict.Action != ActionBlock || !strings.Contains(verdict.Reason, "token validation failed") {
		t.Fatalf("Expected block due to missing token, got verdict: %+v", verdict)
	}

	// 2. Token in comment preface -> should pass (or rewrite with limit)
	commentSQL := "/* conjoiner:conjoiner_valid_token_123 */ SELECT id FROM users WHERE id = 1;"
	verdict, _ = engine.InspectQuery(ctx, "", commentSQL)
	if verdict.Action == ActionBlock {
		t.Fatalf("Expected token in comment to not be blocked, got verdict: %+v", verdict)
	}

	// 3. Invalid token -> should block
	invalidSQL := "/* conjoiner:fake_token */ SELECT id FROM users WHERE id = 1;"
	verdict, _ = engine.InspectQuery(ctx, "", invalidSQL)
	if verdict.Action != ActionBlock {
		t.Fatalf("Expected block with invalid token, got verdict: %+v", verdict)
	}
}
