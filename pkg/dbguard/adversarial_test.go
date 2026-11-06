package dbguard

import (
	"context"
	"strings"
	"testing"
)

func TestAdversarialCommentSmuggling(t *testing.T) {
	engine := NewEngine(DefaultPolicy(), nil)
	ctx := context.Background()

	evasions := []string{
		"DROP/**/TABLE/**/users;",
		"DROP/*multiline\ncomment*/TABLE users;",
		"-- comment\nDROP TABLE users;",
		"/* outer /* inner */ */ DROP TABLE users;",
		"SELECT 1; /* safe prefix */ DROP TABLE accounts;",
	}

	for _, sql := range evasions {
		verdict, err := engine.InspectQuery(ctx, "session_token", sql)
		if err != nil {
			t.Fatalf("Unexpected error for %q: %v", sql, err)
		}
		if verdict.Action != ActionBlock {
			t.Errorf("Adversarial comment smuggling bypassed policy: %q (got %s)", sql, verdict.Action)
		}
	}
}

func TestAdversarialCaseAndWhitespace(t *testing.T) {
	engine := NewEngine(DefaultPolicy(), nil)
	ctx := context.Background()

	cases := []string{
		"dRoP TaBlE users;",
		"DrOp TaBlE users;",
		"DROP\t\r\n  TABLE   \n\t  users;",
		"uPdAtE users sEt role = 'admin';",
		"DeLeTe FrOm users;",
	}

	for _, sql := range cases {
		verdict, err := engine.InspectQuery(ctx, "session_token", sql)
		if err != nil {
			t.Fatalf("Unexpected error for %q: %v", sql, err)
		}
		if verdict.Action != ActionBlock {
			t.Errorf("Adversarial case/whitespace bypassed policy: %q (got %s)", sql, verdict.Action)
		}
	}
}

func TestAdversarialStackedAndChainedQueries(t *testing.T) {
	engine := NewEngine(DefaultPolicy(), nil)
	ctx := context.Background()

	stacked := []string{
		"SELECT 1; DROP TABLE users;",
		"SELECT * FROM items WHERE id = 1; DELETE FROM users; SELECT 2;",
		"BEGIN; UPDATE users SET role = 'admin'; COMMIT;",
		"SELECT 1; TRUNCATE audit_log;",
		"SELECT 1; GRANT ALL ON DATABASE db TO public;",
	}

	for _, sql := range stacked {
		verdict, err := engine.InspectQuery(ctx, "session_token", sql)
		if err != nil {
			t.Fatalf("Unexpected error for %q: %v", sql, err)
		}
		if verdict.Action != ActionBlock {
			t.Errorf("Adversarial stacked query bypassed policy: %q (got %s)", sql, verdict.Action)
		}
	}
}

func TestAdversarialCTEMutations(t *testing.T) {
	engine := NewEngine(DefaultPolicy(), nil)
	ctx := context.Background()

	cteAttacks := []string{
		"WITH purged AS (DELETE FROM sensitive_data RETURNING *) SELECT * FROM purged;",
		"WITH elevated AS (UPDATE users SET is_admin = true RETURNING *) SELECT * FROM elevated;",
	}

	for _, sql := range cteAttacks {
		verdict, err := engine.InspectQuery(ctx, "session_token", sql)
		if err != nil {
			t.Fatalf("Unexpected error for %q: %v", sql, err)
		}
		if verdict.Action != ActionBlock {
			t.Errorf("Adversarial CTE mutation bypassed policy: %q (got %s)", sql, verdict.Action)
		}
	}
}

func TestAdversarialLimitCircumvention(t *testing.T) {
	engine := NewEngine(DefaultPolicy(), nil)
	ctx := context.Background()

	// Attempting to bypass limit cap by setting a massive limit
	sql := "SELECT * FROM secrets LIMIT 999999999;"
	verdict, err := engine.InspectQuery(ctx, "session_token", sql)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if verdict.Action != ActionRewrite {
		t.Fatalf("Expected ActionRewrite, got %s", verdict.Action)
	}
	if !strings.Contains(verdict.RewrittenSQL, "LIMIT 100") {
		t.Fatalf("Expected capped LIMIT 100, got: %s", verdict.RewrittenSQL)
	}
}
