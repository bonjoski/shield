package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/reassembly"
	"github.com/bonjoski/shield/pkg/shield"
)

// Server implements a local loopback reverse proxy providing client-side secret shielding
// for developer AI clients like Cursor, Windsurf, Claude Code, and Antigravity.
type Server struct {
	addr        string
	engine      *shield.Engine
	prov        provider.Provider
	reassembler *reassembly.Reassembler
	httpServer  *http.Server
	mu          sync.Mutex
	running     bool
}

func NewServer(addr string, engine *shield.Engine, prov provider.Provider) *Server {
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	return &Server{
		addr:        addr,
		engine:      engine,
		prov:        prov,
		reassembler: reassembly.NewReassembler(),
	}
}

// Start launches the loopback HTTP server in background.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", s.handleOpenAI)
	mux.HandleFunc("/v1/messages", s.handleAnthropic)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","shield":"active"}`))
	})

	s.httpServer = &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
	}

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	go func() {
		_ = s.httpServer.ListenAndServe()
	}()

	return nil
}

// Stop gracefully shuts down the proxy server.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.httpServer == nil {
		return nil
	}
	s.running = false
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleOpenAI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var reqPayload struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(body, &reqPayload); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	tm := shield.NewTokenMap()
	provMessages := make([]provider.Message, 0, len(reqPayload.Messages))

	// 1. Redact secrets from each user/system message content
	for _, m := range reqPayload.Messages {
		redactedContent, msgTM, err := s.engine.Redact(m.Content)
		if err != nil {
			http.Error(w, fmt.Sprintf("Shield redaction error: %v", err), http.StatusInternalServerError)
			return
		}

		// Merge tokens
		for _, ref := range msgTM.References() {
			sec, _ := msgTM.GetSecret(ref)
			tm.Add(sec, "")
		}

		// 2. Fail-Closed Wire Guard check
		if err := s.engine.FailClosedWireGuard([]byte(redactedContent)); err != nil {
			http.Error(w, fmt.Sprintf("Security violation: %v", err), http.StatusForbidden)
			return
		}

		provMessages = append(provMessages, provider.Message{
			Role:    m.Role,
			Content: redactedContent,
		})
	}

	// 3. Dispatch to pluggable provider
	resp, err := s.prov.Complete(r.Context(), provider.Request{
		Model:    reqPayload.Model,
		Messages: provMessages,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Upstream AI error: %v", err), http.StatusBadGateway)
		return
	}

	// 4. Verify unmapped tokens
	if err := s.reassembler.CheckUnmappedPlaceholders(resp.Content, tm); err != nil {
		if errors.Is(err, reassembly.ErrUnmappedToken) {
			http.Error(w, fmt.Sprintf("Security alert: %v", err), http.StatusBadGateway)
			return
		}
	}

	// 5. Restore tokens locally (or leave sanitized depending on mode)
	restoredContent := s.engine.Restore(resp.Content, tm)

	// Format response to OpenAI schema
	openAIResp := map[string]interface{}{
		"id":      "shield-comp-1",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   resp.Model,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": restoredContent,
				},
				"finish_reason": resp.FinishReason,
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     resp.Usage.InputTokens,
			"completion_tokens": resp.Usage.OutputTokens,
			"total_tokens":      resp.Usage.InputTokens + resp.Usage.OutputTokens,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Shield-Protection", "active")
	_ = json.NewEncoder(w).Encode(openAIResp)
}

func (s *Server) handleAnthropic(w http.ResponseWriter, r *http.Request) {
	// Analogous handling for Anthropic /v1/messages
	s.handleOpenAI(w, r)
}
