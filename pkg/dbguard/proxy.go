package dbguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jackc/pgproto3/v2"

	
	
)

// Config defines the configuration for the Crucible wire 
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

// Start begins listening for client connections and proxying to upstream PostgreSQL.
func (s *Server) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFunc = cancel

	network := "tcp"
	if s.isUnix {
		network = "unix"
		// Clean up stale socket file if it exists
		_ = os.Remove(s.cfg.ListenAddr)
	}

	ln, err := net.Listen(network, s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s (%s): %w", network, s.cfg.ListenAddr, err)
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
		_ = os.Remove(s.cfg.ListenAddr)
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
			// Write single 'N' byte to indicate SSL not supported on this local wire shim
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
			Code:     "08006", // connection_failure
			Message:  fmt.Sprintf("Crucible: failed to connect to upstream PostgreSQL: %v", err),
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
			// Read client auth response and forward to upstream
			clientMsg, err := client.Receive()
			if err != nil {
				return fmt.Errorf("client auth receive error: %w", err)
			}
			if err := upstream.Send(clientMsg); err != nil {
				return fmt.Errorf("upstream auth send error: %w", err)
			}

		case *pgproto3.ReadyForQuery:
			// Handshake complete, connection is ready for queries
			return nil

		case *pgproto3.ErrorResponse:
			return fmt.Errorf("upstream rejected connection: %s", msg.Message)
		}
	}
}

// relayClientToUpstream intercepts client queries and validates them against security 
func (s *Server) relayClientToUpstream(ctx context.Context, sessionToken string, client *pgproto3.Backend, upstream *pgproto3.Frontend) {
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

		switch m := msg.(type) {
		case *pgproto3.Query:
			// Simple query protocol
			verdict, err := s.cfg.Filter.InspectQuery(ctx, sessionToken, m.String)
			if err != nil {
				_ = client.Send(&pgproto3.ErrorResponse{
					Severity: "ERROR",
					Code:     "42501", // insufficient_privilege
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
			// Extended query protocol
			verdict, err := s.cfg.Filter.InspectQuery(ctx, sessionToken, m.Query)
			if err != nil {
				_ = client.Send(&pgproto3.ErrorResponse{
					Severity: "ERROR",
					Code:     "42501",
					Message:  fmt.Sprintf("Crucible policy engine error: %v", err),
				})
				continue
			}

			switch verdict.Action {
			case ActionBlock:
				_ = client.Send(&pgproto3.ErrorResponse{
					Severity: "ERROR",
					Code:     "42501",
					Message:  fmt.Sprintf("Crucible policy violation: %s", verdict.Reason),
				})
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
			// Bind, Execute, Describe, Sync, Flush, Close, etc.
			if err := upstream.Send(m); err != nil {
				return
			}
		}
	}
}

// relayUpstreamToClient forwards backend messages to client and scans data rows for 
func (s *Server) relayUpstreamToClient(ctx context.Context, upstream *pgproto3.Frontend, client *pgproto3.Backend) {
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

		if row, ok := msg.(*pgproto3.DataRow); ok && s.cfg.EntropyScanner != nil {
			maxEnt, exceeded := s.cfg.EntropyScanner.ScanRow(row)
			if exceeded {
				s.cfg.Logger.Printf("ALERT: High Shannon entropy (%.2f bits/byte) detected in result set row", maxEnt)
			}
		}

		if err := client.Send(msg); err != nil {
			return
		}
	}
}
