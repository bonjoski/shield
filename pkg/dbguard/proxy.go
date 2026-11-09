package dbguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jackc/pgproto3/v2"
)

// ErrSocketSymlink is returned when the configured Unix domain socket path is a symlink.
var ErrSocketSymlink = errors.New("security violation: database proxy socket path is a symlink")

// Config defines the configuration for the Crucible wire guard proxy.
type Config struct {
	ListenAddr     string
	UpstreamAddr   string
	Filter         QueryFilter
	EntropyScanner *Scanner
	Logger         *log.Logger
}

// Server is the Crucible database wire-protocol capability shim server.
type Server struct {
	cfg        Config
	listener   net.Listener
	isUnix     bool
	closed     atomic.Bool
	activeWg   sync.WaitGroup
	cancelFunc context.CancelFunc
}

// NewServer creates a new wire proxy server instance.
func NewServer(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("listen address is required")
	}
	if cfg.UpstreamAddr == "" {
		cfg.UpstreamAddr = "127.0.0.1:5432"
	}
	if cfg.Filter == nil {
		cfg.Filter = NewEngine(DefaultPolicy(), nil)
	}
	if cfg.EntropyScanner == nil {
		cfg.EntropyScanner = NewScanner(DefaultThreshold)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "[crucible] ", log.LstdFlags)
	}

	return &Server{
		cfg:    cfg,
		isUnix: isUnixSocket(cfg.ListenAddr),
	}, nil
}

// isUnixSocket returns true if addr is a path to a Unix domain socket.
func isUnixSocket(addr string) bool {
	return strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, "./") || strings.HasSuffix(addr, ".sock")
}

func safeRemoveUnixSocket(sockPath string) error {
	fi, err := os.Lstat(sockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return ErrSocketSymlink
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("security violation: refusing to remove non-socket file %s", sockPath)
	}
	if err := os.Remove(sockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Start begins listening for client connections and proxying to upstream PostgreSQL.
func (s *Server) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFunc = cancel

	network := "tcp"
	if s.isUnix {
		network = "unix"
		if err := safeRemoveUnixSocket(s.cfg.ListenAddr); err != nil {
			return err
		}
		if dir := filepath.Dir(s.cfg.ListenAddr); dir != "" && dir != "." {
			if _, statErr := os.Stat(dir); errors.Is(statErr, os.ErrNotExist) {
				if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
					return fmt.Errorf("failed to create socket directory %s: %w", dir, mkErr)
				}
			}
		}
	}

	ln, err := net.Listen(network, s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s (%s): %w", network, s.cfg.ListenAddr, err)
	}

	if s.isUnix {
		if fi, lerr := os.Lstat(s.cfg.ListenAddr); lerr != nil {
			_ = ln.Close()
			return fmt.Errorf("failed to lstat unix socket %s: %w", s.cfg.ListenAddr, lerr)
		} else if fi.Mode()&os.ModeSymlink != 0 {
			_ = ln.Close()
			return ErrSocketSymlink
		}
		if chmodErr := os.Chmod(s.cfg.ListenAddr, 0600); chmodErr != nil {
			_ = ln.Close()
			_ = safeRemoveUnixSocket(s.cfg.ListenAddr)
			return fmt.Errorf("failed to enforce 0600 permissions on unix socket %s: %w", s.cfg.ListenAddr, chmodErr)
		}
	}

	s.listener = ln
	s.cfg.Logger.Printf("Crucible proxy listening on %s (%s), upstream %s", s.cfg.ListenAddr, network, s.cfg.UpstreamAddr)

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			return err
		}

		s.activeWg.Add(1)
		go func(c net.Conn) {
			defer s.activeWg.Done()
			s.handleClient(ctx, c)
		}(clientConn)
	}
}

// Close gracefully closes the proxy listener and cleans up unix domain sockets.
func (s *Server) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	if s.isUnix {
		if rmErr := safeRemoveUnixSocket(s.cfg.ListenAddr); rmErr != nil && err == nil {
			err = rmErr
		}
	}
	return err
}

// Addr returns the network address the server is listening on.
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// handleClient manages a single client PostgreSQL session.
func (s *Server) handleClient(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	clientBackend := pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn)

	// 1. Receive initial startup or SSL message
	startupMsg, err := clientBackend.ReceiveStartupMessage()
	if err != nil {
		s.cfg.Logger.Printf("error receiving startup message: %v", err)
		return
	}

	// 2. Handle SSLRequest or GSSEncRequest: decline TLS over local socket
	for {
		if _, ok := startupMsg.(*pgproto3.SSLRequest); ok {
			if _, err := clientConn.Write([]byte{'N'}); err != nil {
				return
			}
			startupMsg, err = clientBackend.ReceiveStartupMessage()
			if err != nil {
				return
			}
			continue
		}
		if _, ok := startupMsg.(*pgproto3.GSSEncRequest); ok {
			if _, err := clientConn.Write([]byte{'N'}); err != nil {
				return
			}
			startupMsg, err = clientBackend.ReceiveStartupMessage()
			if err != nil {
				return
			}
			continue
		}
		break
	}

	start, ok := startupMsg.(*pgproto3.StartupMessage)
	if !ok {
		s.cfg.Logger.Printf("expected StartupMessage, got %T", startupMsg)
		return
	}

	// 3. Extract Conjoiner session token from application_name parameter
	sessionToken := ""
	if appName, exists := start.Parameters["application_name"]; exists {
		if strings.HasPrefix(appName, "conjoiner:") {
			sessionToken = strings.TrimPrefix(appName, "conjoiner:")
		}
	}

	// 4. Connect to upstream PostgreSQL
	upstreamNetwork := "tcp"
	if isUnixSocket(s.cfg.UpstreamAddr) {
		upstreamNetwork = "unix"
	}

	upstreamConn, err := net.Dial(upstreamNetwork, s.cfg.UpstreamAddr)
	if err != nil {
		s.cfg.Logger.Printf("failed to connect to upstream %s: %v", s.cfg.UpstreamAddr, err)
		_ = clientBackend.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "08006",
			Message:  "Crucible: failed to connect to upstream PostgreSQL",
		})
		return
	}
	defer upstreamConn.Close()

	upstreamFrontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(upstreamConn), upstreamConn)

	// Forward StartupMessage upstream
	if err := upstreamFrontend.Send(start); err != nil {
		s.cfg.Logger.Printf("failed to send startup to upstream: %v", err)
		return
	}

	// 5. Authentication & Startup Phase Handshake
	if err := s.handshake(clientBackend, upstreamFrontend); err != nil {
		s.cfg.Logger.Printf("startup handshake failed: %v", err)
		return
	}

	// 6. Active Query Relay Phase
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine: Client -> Upstream
	go func() {
		defer wg.Done()
		defer sessionCancel()
		s.relayClientToUpstream(sessionCtx, sessionToken, clientBackend, upstreamFrontend)
	}()

	// Goroutine: Upstream -> Client
	go func() {
		defer wg.Done()
		defer sessionCancel()
		s.relayUpstreamToClient(sessionCtx, upstreamFrontend, clientBackend)
	}()

	wg.Wait()
}

// handshake manages the authentication flow between client and upstream.
func (s *Server) handshake(client *pgproto3.Backend, upstream *pgproto3.Frontend) error {
	for {
		backendMsg, err := upstream.Receive()
		if err != nil {
			return fmt.Errorf("upstream receive error during handshake: %w", err)
		}

		if err := client.Send(backendMsg); err != nil {
			return fmt.Errorf("client send error during handshake: %w", err)
		}

		switch msg := backendMsg.(type) {
		case *pgproto3.AuthenticationCleartextPassword,
			*pgproto3.AuthenticationMD5Password,
			*pgproto3.AuthenticationSASL,
			*pgproto3.AuthenticationSASLContinue,
			*pgproto3.AuthenticationSASLFinal:
			clientMsg, err := client.Receive()
			if err != nil {
				return fmt.Errorf("client auth receive error: %w", err)
			}
			if err := upstream.Send(clientMsg); err != nil {
				return fmt.Errorf("upstream auth send error: %w", err)
			}

		case *pgproto3.ReadyForQuery:
			return nil

		case *pgproto3.ErrorResponse:
			return fmt.Errorf("upstream rejected connection: %s", msg.Message)
		}
	}
}

// relayClientToUpstream intercepts client queries and validates them against security policy.
// When an Extended Query protocol Parse message is blocked, subsequent pipelined Bind/Describe/Execute
// frames are drained up to Sync ('S') per the PostgreSQL v3 wire specification so framing stays synchronized
// and previously prepared statements on upstream can never be executed by pipelined frames.
func (s *Server) relayClientToUpstream(ctx context.Context, sessionToken string, client *pgproto3.Backend, upstream *pgproto3.Frontend) {
	discardUntilSync := false

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := client.Receive()
		if err != nil {
			return
		}

		if discardUntilSync {
			switch m := msg.(type) {
			case *pgproto3.Sync:
				discardUntilSync = false
				_ = client.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			case *pgproto3.Terminate:
				_ = upstream.Send(m)
				return
			default:
				// Discard pipelined Bind, Describe, Execute, Flush, Close, etc. until Sync
			}
			continue
		}

		switch m := msg.(type) {
		case *pgproto3.Query:
			verdict, err := s.cfg.Filter.InspectQuery(ctx, sessionToken, m.String)
			if err != nil {
				_ = client.Send(&pgproto3.ErrorResponse{
					Severity: "ERROR",
					Code:     "42501",
					Message:  fmt.Sprintf("Crucible policy engine error: %v", err),
				})
				_ = client.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				continue
			}

			switch verdict.Action {
			case ActionBlock:
				_ = client.Send(&pgproto3.ErrorResponse{
					Severity: "ERROR",
					Code:     "42501",
					Message:  fmt.Sprintf("Crucible policy violation: %s", verdict.Reason),
				})
				_ = client.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				continue

			case ActionRewrite:
				m.String = verdict.RewrittenSQL
				if err := upstream.Send(m); err != nil {
					return
				}

			case ActionPass:
				if err := upstream.Send(m); err != nil {
					return
				}
			}

		case *pgproto3.Parse:
			verdict, err := s.cfg.Filter.InspectQuery(ctx, sessionToken, m.Query)
			if err != nil {
				_ = client.Send(&pgproto3.ErrorResponse{
					Severity: "ERROR",
					Code:     "42501",
					Message:  fmt.Sprintf("Crucible policy engine error: %v", err),
				})
				discardUntilSync = true
				continue
			}

			switch verdict.Action {
			case ActionBlock:
				_ = client.Send(&pgproto3.ErrorResponse{
					Severity: "ERROR",
					Code:     "42501",
					Message:  fmt.Sprintf("Crucible policy violation: %s", verdict.Reason),
				})
				discardUntilSync = true
				continue

			case ActionRewrite:
				m.Query = verdict.RewrittenSQL
				if err := upstream.Send(m); err != nil {
					return
				}

			case ActionPass:
				if err := upstream.Send(m); err != nil {
					return
				}
			}

		case *pgproto3.Terminate:
			_ = upstream.Send(m)
			return

		default:
			if err := upstream.Send(m); err != nil {
				return
			}
		}
	}
}

func zeroizeRowValues(row *pgproto3.DataRow) {
	if row == nil {
		return
	}
	for _, col := range row.Values {
		for i := range col {
			col[i] = 0
		}
		runtime.KeepAlive(col)
	}
}

// relayUpstreamToClient forwards backend messages to client and fails closed on high-entropy
// or secret-bearing DataRow payloads, suppressing leaked rows and emitting an ErrorResponse
// while keeping wire framing synchronized up to ReadyForQuery.
func (s *Server) relayUpstreamToClient(ctx context.Context, upstream *pgproto3.Frontend, client *pgproto3.Backend) {
	suppressResultUntilReady := false

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := upstream.Receive()
		if err != nil {
			return
		}

		if suppressResultUntilReady {
			switch m := msg.(type) {
			case *pgproto3.DataRow:
				zeroizeRowValues(m)
				continue
			case *pgproto3.CommandComplete, *pgproto3.PortalSuspended, *pgproto3.EmptyQueryResponse:
				continue
			case *pgproto3.ReadyForQuery:
				suppressResultUntilReady = false
				if err := client.Send(m); err != nil {
					return
				}
				continue
			}
		}

		if row, ok := msg.(*pgproto3.DataRow); ok && s.cfg.EntropyScanner != nil {
			maxEnt, exceeded := s.cfg.EntropyScanner.ScanRow(row)
			if exceeded {
				s.cfg.Logger.Printf("BLOCKED: High Shannon entropy (%.2f bits/byte) or secret detected in result set row", maxEnt)
				zeroizeRowValues(row)
				suppressResultUntilReady = true
				if err := client.Send(&pgproto3.ErrorResponse{
					Severity: "ERROR",
					Code:     "42501",
					Message:  fmt.Sprintf("Crucible policy violation: result row blocked due to high entropy (%.2f bits/byte) or credential leakage", maxEnt),
				}); err != nil {
					return
				}
				continue
			}
		}

		if err := client.Send(msg); err != nil {
			return
		}
	}
}
