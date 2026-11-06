package dbguard

import (
	"strings"
	"testing"
)

func TestInspectDDL(t *testing.T) {
	queries := []struct {
		sql     string
		ddlType string
	}{
		{"DROP TABLE users;", "DROP"},
		{"DROP VIEW v_users CASCADE;", "DROP"},
		{"DROP INDEX idx_users_email;", "DROP"},
		{"ALTER TABLE users ADD COLUMN is_admin boolean;", "ALTER TABLE"},
		{"TRUNCATE users;", "TRUNCATE"},
	}

	for _, tc := range queries {
		tree, err := Parse(tc.sql)
		if err != nil {
			t.Fatalf("Failed to parse %q: %v", tc.sql, err)
		}
		res, err := Inspect(tree)
		if err != nil {
			t.Fatalf("Failed to inspect %q: %v", tc.sql, err)
		}
		if !res.HasDDL {
			t.Errorf("Expected HasDDL for %q", tc.sql)
		}
		if !strings.HasPrefix(res.DDLType, tc.ddlType) {
			t.Errorf("Expected DDLType starting with %q, got %q for %q", tc.ddlType, res.DDLType, tc.sql)
		}
	}
}

func TestInspectPrivilegeEscalation(t *testing.T) {
	queries := []string{
		"GRANT ALL PRIVILEGES ON DATABASE app TO dev;",
		"CREATE ROLE superuser_agent WITH SUPERUSER;",
		"ALTER ROLE dev WITH SUPERUSER;",
	}

	for _, sql := range queries {
		tree, err := Parse(sql)
		if err != nil {
			t.Fatalf("Failed to parse %q: %v", sql, err)
		}
		res, err := Inspect(tree)
		if err != nil {
			t.Fatalf("Failed to inspect %q: %v", sql, err)
		}
		if !res.HasPrivilegeEscalation {
			t.Errorf("Expected HasPrivilegeEscalation for %q", sql)
		}
	}
}

func TestInspectMutations(t *testing.T) {
	// Blocked unconstrained mutations
	blocked := []string{
		"UPDATE users SET is_active = false;",
		"DELETE FROM users;",
		"WITH purged AS (DELETE FROM users RETURNING *) SELECT * FROM purged;",
	}
	for _, sql := range blocked {
		tree, err := Parse(sql)
		if err != nil {
			t.Fatalf("Failed to parse %q: %v", sql, err)
		}
		res, err := Inspect(tree)
		if err != nil {
			t.Fatalf("Failed to inspect %q: %v", sql, err)
		}
		if !res.HasUnconstrainedMutation {
			t.Errorf("Expected HasUnconstrainedMutation for %q", sql)
		}
	}

	// Allowed constrained mutations
	allowed := []string{
		"UPDATE users SET is_active = false WHERE id = 42;",
		"DELETE FROM users WHERE status = 'pending' AND created_at < NOW();",
	}
	for _, sql := range allowed {
		tree, err := Parse(sql)
		if err != nil {
			t.Fatalf("Failed to parse %q: %v", sql, err)
		}
		res, err := Inspect(tree)
		if err != nil {
			t.Fatalf("Failed to inspect %q: %v", sql, err)
		}
		if res.HasUnconstrainedMutation {
			t.Errorf("Expected constrained mutation to pass without HasUnconstrainedMutation: %q (got %s)", sql, res.UnconstrainedMutationType)
		}
	}
}

func TestInspectStackedQueries(t *testing.T) {
	stacked := "SELECT id FROM users; DROP TABLE secret_keys; SELECT 1;"
	tree, err := Parse(stacked)
	if err != nil {
		t.Fatalf("Failed to parse stacked: %v", err)
	}
	res, err := Inspect(tree)
	if err != nil {
		t.Fatalf("Failed to inspect: %v", err)
	}
	if res.StatementCount != 3 {
		t.Errorf("Expected 3 statements, got %d", res.StatementCount)
	}
	if !res.HasDDL {
		t.Errorf("Expected stacked query with DROP to have HasDDL")
	}
}

func TestEnforceLimit(t *testing.T) {
	// 1. Unbounded select
	unbounded := "SELECT id, name FROM users"
	tree, err := Parse(unbounded)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	rewritten, modified, err := EnforceLimit(tree, 100)
	if err != nil {
		t.Fatalf("EnforceLimit error: %v", err)
	}
	if !modified {
		t.Fatalf("Expected modified=true for unbounded SELECT")
	}
	if !strings.Contains(rewritten, "LIMIT 100") {
		t.Fatalf("Expected 'LIMIT 100' in rewritten query: %s", rewritten)
	}

	// 2. Select with smaller limit (50) should NOT be modified
	smallLimit := "SELECT id, name FROM users LIMIT 50"
	tree, err = Parse(smallLimit)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	_, modified, err = EnforceLimit(tree, 100)
	if err != nil {
		t.Fatalf("EnforceLimit error: %v", err)
	}
	if modified {
		t.Fatalf("Expected modified=false for SELECT with LIMIT 50")
	}

	// 3. Select with excessive limit (50000) should be capped to 100
	hugeLimit := "SELECT id, name FROM users LIMIT 50000"
	tree, err = Parse(hugeLimit)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	rewritten, modified, err = EnforceLimit(tree, 100)
	if err != nil {
		t.Fatalf("EnforceLimit error: %v", err)
	}
	if !modified {
		t.Fatalf("Expected modified=true for SELECT with excessive limit")
	}
	if !strings.Contains(rewritten, "LIMIT 100") {
		t.Fatalf("Expected capped 'LIMIT 100' in rewritten query: %s", rewritten)
	}
}
