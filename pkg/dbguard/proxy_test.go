package dbguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"

	
	
)

// mockPostgresServer acts as an upstream PostgreSQL server for wire protocol unit testing.
type mockPostgresServer struct {
	listener net.Listener
	receivedQueries []string
	mu sync.Mutex
}

func startMockPostgres(t *testing.T) *mockPostgresServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock postgres listener: %v", err)
	}

	mock := &mockPostgresServer{
		listener: ln,
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go mock.handleConn(conn)
		}
	}()

	return mock
}

func (m *mockPostgresServer) handleConn(conn net.Conn) {
	defer conn.Close()

	backend := pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)
	startupMsg, err := backend.ReceiveStartupMessage()
	if err != nil {
		return
	}

	// Handle SSL request if any
	if _, ok := startupMsg.(*pgproto3.SSLRequest); ok {
		_, _ = conn.Write([]byte{'N'})
		_, _ = backend.ReceiveStartupMessage()
	}

	// Send Auth OK and ReadyForQuery
	_ = backend.Send(&pgproto3.AuthenticationOk{})
	_ = backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0"})
	_ = backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	for {
		msg, err := backend.Receive()
		if err != nil {
			return
		}

		switch mType := msg.(type) {
		case *pgproto3.Query:
			m.mu.Lock()
			m.receivedQueries = append(m.receivedQueries, mType.String)
			m.mu.Unlock()

			// Reply with dummy row
			_ = backend.Send(&pgproto3.RowDescription{
				Fields: []pgproto3.FieldDescription{
					{Name: []byte("id"), TableOID: 0, TableAttributeNumber: 1, DataTypeOID: 23, DataTypeSize: 4, TypeModifier: -1, Format: 0},
					{Name: []byte("name"), TableOID: 0, TableAttributeNumber: 2, DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, Format: 0},
				},
			})
			_ = backend.Send(&pgproto3.DataRow{
				Values: [][]byte{
					[]byte("1"),
					[]byte("Alice"),
				},
			})
			_ = backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			_ = backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

		case *pgproto3.Terminate:
			return
		}
	}
}

func (m *mockPostgresServer) Close() {
	if m.listener != nil {
		_ = m.listener.Close()
	}
}

func (m *mockPostgresServer) GetReceivedQueries() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]string, len(m.receivedQueries))
	copy(res, m.receivedQueries)
	return res
}

func TestProxyWireProtocolInterception(t *testing.T) {
	// 1. Start mock PostgreSQL server
	mockUpstream := startMockPostgres(t)
	defer mockUpstream.Close()

	// 2. Set up Crucible proxy on temporary Unix Domain Socket (short path for macOS sockaddr_un 104-byte limit)
	proxySocket := fmt.Sprintf("/tmp/cr-%d.sock", time.Now().UnixNano())
	defer os.Remove(proxySocket)

	server, err := NewServer(Config{
		ListenAddr:   proxySocket,
		UpstreamAddr: mockUpstream.listener.Addr().String(),
		Filter:       NewEngine(DefaultPolicy(), nil),
		EntropyScanner: NewScanner(5.0),
	})
	if err != nil {
		t.Fatalf("Failed to initialize Crucible server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverStarted := make(chan struct{})
	go func() {
		close(serverStarted)
		_ = server.Start(ctx)
	}()

	<-serverStarted
	// Wait brief moment for socket to be created
	time.Sleep(50 * time.Millisecond)
	defer server.Close()

	// 3. Connect client to Crucible proxy Unix Domain Socket
	clientConn, err := net.Dial("unix", proxySocket)
	if err != nil {
		t.Fatalf("Client failed to dial Crucible socket %s: %v", proxySocket, err)
	}
	defer clientConn.Close()

	clientFrontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(clientConn), clientConn)

	// Send StartupMessage
	err = clientFrontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":             "agent_test",
			"database":         "app_db",
			"application_name": "conjoiner:tok_subagent_session_abc123",
		},
	})
	if err != nil {
		t.Fatalf("Client failed to send startup message: %v", err)
	}

	// Read until ReadyForQuery
	for {
		msg, err := clientFrontend.Receive()
		if err != nil {
			t.Fatalf("Client handshake receive error: %v", err)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}

	// 4. Test Case 1: Send Destructive DDL "DROP TABLE users;"
	err = clientFrontend.Send(&pgproto3.Query{String: "DROP TABLE users;"})
	if err != nil {
		t.Fatalf("Failed to send DROP TABLE query: %v", err)
	}

	// Expect ErrorResponse from Crucible
	resp, err := clientFrontend.Receive()
	if err != nil {
		t.Fatalf("Failed to receive response to DROP TABLE: %v", err)
	}
	errResp, ok := resp.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("Expected ErrorResponse, got %T: %+v", resp, resp)
	}
	if !strings.Contains(errResp.Message, "Crucible policy violation") || !strings.Contains(errResp.Message, "DROP") {
		t.Fatalf("Unexpected error message: %s", errResp.Message)
	}

	// Next message must be ReadyForQuery so client can continue
	resp, err = clientFrontend.Receive()
	if err != nil {
		t.Fatalf("Failed to receive ReadyForQuery: %v", err)
	}
	if _, ok := resp.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("Expected ReadyForQuery after error, got %T", resp)
	}

	// Verify upstream NEVER received the DROP TABLE query
	for _, q := range mockUpstream.GetReceivedQueries() {
		if strings.Contains(q, "DROP TABLE") {
			t.Fatalf("CRITICAL SECURITY FAILURE: Upstream PostgreSQL received blocked DROP TABLE query: %s", q)
		}
	}

	// 5. Test Case 2: Send Unconstrained Mutation "DELETE FROM users;"
	err = clientFrontend.Send(&pgproto3.Query{String: "DELETE FROM users;"})
	if err != nil {
		t.Fatalf("Failed to send DELETE query: %v", err)
	}
	resp, err = clientFrontend.Receive()
	if err != nil {
		t.Fatalf("Failed to receive response to DELETE: %v", err)
	}
	errResp, ok = resp.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("Expected ErrorResponse for unconstrained DELETE, got %T", resp)
	}
	if !strings.Contains(errResp.Message, "Crucible policy violation") || !strings.Contains(errResp.Message, "without WHERE") {
		t.Fatalf("Unexpected error message for DELETE: %s", errResp.Message)
	}

	resp, err = clientFrontend.Receive()
	if err != nil {
		t.Fatalf("Failed to receive ReadyForQuery after DELETE: %v", err)
	}
	if _, ok := resp.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("Expected ReadyForQuery, got %T", resp)
	}

	// 6. Test Case 3: Send Safe Constrained Query "SELECT * FROM users WHERE id = 1"
	err = clientFrontend.Send(&pgproto3.Query{String: "SELECT * FROM users WHERE id = 1"})
	if err != nil {
		t.Fatalf("Failed to send safe SELECT: %v", err)
	}

	// Read query results: RowDescription, DataRow, CommandComplete, ReadyForQuery
	var receivedRow *pgproto3.DataRow
	for {
		resp, err = clientFrontend.Receive()
		if err != nil {
			t.Fatalf("Failed reading SELECT response: %v", err)
		}
		if row, ok := resp.(*pgproto3.DataRow); ok {
			receivedRow = row
		}
		if _, ok := resp.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}

	if receivedRow == nil {
		t.Fatalf("Expected DataRow from safe SELECT, got nil")
	}
	if string(receivedRow.Values[1]) != "Alice" {
		t.Fatalf("Expected name 'Alice', got %s", string(receivedRow.Values[1]))
	}

	// Verify upstream did receive the safe query (with LIMIT injected if unbounded)
	upstreamQueries := mockUpstream.GetReceivedQueries()
	if len(upstreamQueries) == 0 {
		t.Fatalf("Expected upstream to receive safe SELECT query")
	}
	t.Logf("Upstream received query: %s", upstreamQueries[0])
	if !strings.Contains(upstreamQueries[0], "WHERE id = 1") {
		t.Fatalf("Upstream received unexpected query: %s", upstreamQueries[0])
	}
}

func TestProxySocketCleanup(t *testing.T) {
	sockPath := fmt.Sprintf("/tmp/cr-clean-%d.sock", time.Now().UnixNano())
	defer os.Remove(sockPath)

	server, err := NewServer(Config{
		ListenAddr:   sockPath,
		UpstreamAddr: "127.0.0.1:5432",
	})
	if err != nil {
		t.Fatalf("Failed NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	go func() {
		close(started)
		_ = server.Start(ctx)
	}()

	<-started
	time.Sleep(30 * time.Millisecond)

	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		t.Fatalf("Expected socket file %s to exist while server running", sockPath)
	}

	cancel()
	_ = server.Close()

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("Expected socket file %s to be cleaned up after Close()", sockPath)
	}
}
