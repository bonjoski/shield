package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGateway_UnauthenticatedLocalRequestsRejected401(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer mockUpstream.Close()

	retriever := NewMockSecretRetriever(map[string][]byte{
		"openai/api-key": []byte("sk-upstream-secret-12345"),
	})

	cfg := Config{
		ListenAddr:      "127.0.0.1:0",
		UpstreamURL:     mockUpstream.URL,
		VaultSecret:     "openai/api-key",
		AuthToken:       "gateway-client-secret-token",
		SecretRetriever: retriever,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client := &http.Client{}

	tests := []struct {
		name       string
		headers    map[string]string
		wantStatus int
	}{
		{
			name:       "Missing auth header",
			headers:    nil,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Invalid bearer token",
			headers: map[string]string{
				"Authorization": "Bearer wrong-token",
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Invalid x-api-key",
			headers: map[string]string{
				"x-api-key": "wrong-token",
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Valid bearer token",
			headers: map[string]string{
				"Authorization": "Bearer gateway-client-secret-token",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Valid x-api-key",
			headers: map[string]string{
				"x-api-key": "gateway-client-secret-token",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Valid api-key header",
			headers: map[string]string{
				"api-key": "gateway-client-secret-token",
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, srv.URL()+"/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o"}`))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("status code = %d, want %d; body: %s", resp.StatusCode, tc.wantStatus, string(body))
			}

			if tc.wantStatus == http.StatusUnauthorized {
				var errResp map[string]map[string]any
				if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
					t.Fatalf("failed to parse error response JSON: %v", err)
				}
				if errResp["error"]["type"] != "auth_error" {
					t.Errorf("expected error.type = 'auth_error', got %v", errResp["error"]["type"])
				}
			}
		})
	}
}

func TestGateway_StreamingCompletion(t *testing.T) {
	expectedSecret := "sk-upstream-secret-streaming-789"
	var receivedAuthHeader string
	var upstreamReceivedPath string

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		upstreamReceivedPath = r.URL.Path

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("mock server writer must be flusher")
		}

		chunks := []string{
			"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n",
			"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\" world!\"}}]}\n\n",
			"data: [DONE]\n\n",
		}

		for _, chunk := range chunks {
			_, _ = w.Write([]byte(chunk))
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer mockUpstream.Close()

	retriever := NewMockSecretRetriever(map[string][]byte{
		"openai/api-key": []byte(expectedSecret),
	})

	cfg := Config{
		ListenAddr:      "127.0.0.1:0",
		UpstreamURL:     mockUpstream.URL + "/v1",
		VaultSecret:     "openai/api-key",
		AuthToken:       "shield-keyless-managed",
		SecretRetriever: retriever,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	reqBody := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"Hi"}]}`
	req, err := http.NewRequest(http.MethodPost, srv.URL()+"/v1/chat/completions", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer shield-keyless-managed")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code %d", resp.StatusCode)
	}

	if resp.Header.Get("X-Shield-Gateway") != "keyless-enclave-active" {
		t.Errorf("missing or invalid X-Shield-Gateway header: %s", resp.Header.Get("X-Shield-Gateway"))
	}

	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Errorf("expected Content-Type text/event-stream, got: %s", resp.Header.Get("Content-Type"))
	}

	// Verify upstream received the right Authorization header with the secret
	if receivedAuthHeader != "Bearer "+expectedSecret {
		t.Errorf("upstream received auth header %q, want %q", receivedAuthHeader, "Bearer "+expectedSecret)
	}

	// Verify upstream path was properly joined without /v1/v1 duplication
	if upstreamReceivedPath != "/v1/chat/completions" {
		t.Errorf("upstream received path %q, want %q", upstreamReceivedPath, "/v1/chat/completions")
	}

	// Read streamed content
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response stream: %v", err)
	}

	content := string(bodyBytes)
	if !strings.Contains(content, "Hello") || !strings.Contains(content, "world!") || !strings.Contains(content, "[DONE]") {
		t.Errorf("streaming response missing expected chunks; got: %s", content)
	}
}

func TestGateway_UpstreamSecretZeroizedAndNeverLogged(t *testing.T) {
	secretValue := "sk-super-secret-key-to-zeroize-and-redact-999"
	clientToken := "client-bearer-token-abc-12345"

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-test","object":"chat.completion"}`))
	}))
	defer mockUpstream.Close()

	retriever := NewMockSecretRetriever(map[string][]byte{
		"openai/api-key": []byte(secretValue),
	})

	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "[gateway_test] ", 0)

	cfg := Config{
		ListenAddr:      "127.0.0.1:0",
		UpstreamURL:     mockUpstream.URL,
		VaultSecret:     "openai/api-key",
		AuthToken:       clientToken,
		SecretRetriever: retriever,
		Logger:          logger,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	// Execute completion request
	req, err := http.NewRequest(http.MethodPost, srv.URL()+"/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o"}`))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+clientToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// 1. Verify Secret Buffer Zeroization in RAM
	lastSec := retriever.LastReturnedSecret()
	if lastSec == nil {
		t.Fatal("retriever did not record last returned secret")
	}
	if !lastSec.IsZeroized() {
		t.Errorf("CRITICAL SECURITY FAILURE: secret was NOT zeroized upon connection close; bytes = %v", lastSec.Bytes())
	}

	// 2. Verify Upstream Secret and Client Token were NEVER written to debug logs
	logOutput := logBuf.String()
	if strings.Contains(logOutput, secretValue) {
		t.Errorf("CRITICAL SECURITY FAILURE: upstream secret found in debug logs!\nLog output:\n%s", logOutput)
	}
	if strings.Contains(logOutput, clientToken) {
		t.Errorf("CRITICAL SECURITY FAILURE: client auth token found in debug logs!\nLog output:\n%s", logOutput)
	}

	// 3. Test RedactingLogger directly to assert patterns are scrubbed
	rl := NewRedactingLogger(logger, secretValue, clientToken)
	rl.Printf("Testing debug log with Authorization: Bearer %s and x-api-key: %s", secretValue, clientToken)
	finalLog := logBuf.String()
	if strings.Contains(finalLog, secretValue) {
		t.Errorf("RedactingLogger failed to scrub secret from Printf")
	}
	if strings.Contains(finalLog, clientToken) {
		t.Errorf("RedactingLogger failed to scrub clientToken from Printf")
	}
}

func TestGateway_CompatibleWithLiteLLM_Dify(t *testing.T) {
	var requestedPaths []string
	var receivedMethods []string

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		receivedMethods = append(receivedMethods, r.Method)

		switch r.URL.Path {
		case "/v1/chat/completions":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"id": "chatcmpl-litellm-1",
				"object": "chat.completion",
				"created": 1700000000,
				"model": "gpt-4o",
				"choices": [
					{
						"index": 0,
						"message": {
							"role": "assistant",
							"content": "LiteLLM / Dify compatible response"
						},
						"finish_reason": "stop"
					}
				],
				"usage": {
					"prompt_tokens": 12,
					"completion_tokens": 6,
					"total_tokens": 18
				}
			}`))
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"object": "list",
				"data": [
					{"id": "gpt-4o", "object": "model"}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockUpstream.Close()

	retriever := NewMockSecretRetriever(map[string][]byte{
		"openai/api-key": []byte("sk-litellm-upstream-key"),
	})

	cfg := Config{
		ListenAddr:      "127.0.0.1:0",
		UpstreamURL:     mockUpstream.URL + "/v1",
		VaultSecret:     "openai/api-key",
		AuthToken:       "shield-keyless-managed",
		SecretRetriever: retriever,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client := &http.Client{}

	// Test 1: Standard LiteLLM chat completion call
	litellmReqBody := `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "Tell me a joke"}],
		"temperature": 0.7
	}`

	req, err := http.NewRequest(http.MethodPost, srv.URL()+"/v1/chat/completions", strings.NewReader(litellmReqBody))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer shield-keyless-managed")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("LiteLLM chat request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var chatResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		t.Fatalf("failed to decode JSON completion: %v", err)
	}

	choices, ok := chatResp["choices"].([]any)
	if !ok || len(choices) == 0 {
		t.Fatalf("invalid choices structure in response: %v", chatResp)
	}
	firstChoice := choices[0].(map[string]any)
	msg := firstChoice["message"].(map[string]any)
	if msg["content"] != "LiteLLM / Dify compatible response" {
		t.Errorf("unexpected content: %v", msg["content"])
	}

	// Test 2: Models list endpoint (/v1/models)
	modelsReq, err := http.NewRequest(http.MethodGet, srv.URL()+"/v1/models", nil)
	if err != nil {
		t.Fatalf("failed to create models request: %v", err)
	}
	modelsReq.Header.Set("Authorization", "Bearer shield-keyless-managed")

	modelsResp, err := client.Do(modelsReq)
	if err != nil {
		t.Fatalf("models request failed: %v", err)
	}
	defer modelsResp.Body.Close()

	if modelsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for /v1/models, got %d", modelsResp.StatusCode)
	}

	// Verify paths passed through to upstream without /v1/v1 duplication
	expectedPaths := []string{"/v1/chat/completions", "/v1/models"}
	if len(requestedPaths) != len(expectedPaths) {
		t.Fatalf("expected %d requests, got %d", len(expectedPaths), len(requestedPaths))
	}
	for i, want := range expectedPaths {
		if requestedPaths[i] != want {
			t.Errorf("request %d path = %q, want %q", i, requestedPaths[i], want)
		}
	}
}

func TestGateway_LocksmithUDSRetriever(t *testing.T) {
	tempDir, err := os.MkdirTemp("/tmp", "gw-ls")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	sockPath := filepath.Join(tempDir, "ls.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on mock locksmith socket: %v", err)
	}
	defer l.Close()

	expectedSecret := "sk-uds-locksmith-hardware-secret-777"
	var receivedLeaseSecretName string

	// Serve mock Locksmith daemon
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil {
					return
				}

				var req etxLeaseRequest
				if err := json.Unmarshal(buf[:n], &req); err != nil {
					return
				}
				receivedLeaseSecretName = req.SecretName

				// Respond with GRANTED
				resp := etxLeaseResponse{
					Status:      "GRANTED",
					LeaseID:     "ls-lease-mock-1",
					SecretValue: json.RawMessage(fmt.Sprintf("%q", expectedSecret)),
				}
				_ = json.NewEncoder(c).Encode(resp)
			}(conn)
		}
	}()

	var upstreamReceivedAuth string
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReceivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	retriever := NewLocksmithRetriever(sockPath)

	cfg := Config{
		ListenAddr:      "127.0.0.1:0",
		UpstreamURL:     mockUpstream.URL,
		VaultSecret:     "openai/api-key",
		SecretRetriever: retriever,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	req, err := http.NewRequest(http.MethodPost, srv.URL()+"/v1/chat/completions", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	if receivedLeaseSecretName != "openai/api-key" {
		t.Errorf("locksmith socket received secret_name %q, want 'openai/api-key'", receivedLeaseSecretName)
	}

	if upstreamReceivedAuth != "Bearer "+expectedSecret {
		t.Errorf("upstream received auth %q, want 'Bearer %s'", upstreamReceivedAuth, expectedSecret)
	}
}

func TestGateway_EnvironmentFallback(t *testing.T) {
	envKey := "TEST_ENV_FALLBACK_SECRET_KEY"
	secretVal := "sk-fallback-from-env-333"
	t.Setenv(envKey, secretVal)

	var upstreamReceivedAuth string
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReceivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	// Empty socket path ensures Locksmith UDS is bypassed
	retriever := NewLocksmithRetriever("/non/existent/sock/path")

	cfg := Config{
		ListenAddr:      "127.0.0.1:0",
		UpstreamURL:     mockUpstream.URL,
		VaultSecret:     envKey,
		SecretRetriever: retriever,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	req, err := http.NewRequest(http.MethodPost, srv.URL()+"/v1/chat/completions", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	if upstreamReceivedAuth != "Bearer "+secretVal {
		t.Errorf("upstream received auth %q, want 'Bearer %s'", upstreamReceivedAuth, secretVal)
	}
}

func TestGateway_Adversarial_LoopbackEnforcement(t *testing.T) {
	disallowedAddrs := []string{
		"0.0.0.0:8080",
		"192.168.1.50:8080",
		"10.0.0.5:8080",
		"172.16.0.1:8080",
		"8.8.8.8:8080",
	}

	for _, addr := range disallowedAddrs {
		t.Run(addr, func(t *testing.T) {
			cfg := Config{
				ListenAddr:  addr,
				UpstreamURL: "https://api.openai.com/v1",
			}
			_, err := NewServer(cfg)
			if err == nil {
				t.Fatalf("expected NewServer to reject non-loopback address %s", addr)
			}
			if !strings.Contains(err.Error(), "loopback") {
				t.Errorf("expected error mentioning loopback, got: %v", err)
			}
		})
	}

	allowedAddrs := []string{
		"127.0.0.1:8080",
		"localhost:8080",
		"[::1]:8080",
	}

	for _, addr := range allowedAddrs {
		t.Run(addr, func(t *testing.T) {
			cfg := Config{
				ListenAddr:  addr,
				UpstreamURL: "https://api.openai.com/v1",
			}
			srv, err := NewServer(cfg)
			if err != nil {
				t.Fatalf("expected NewServer to accept loopback address %s, got: %v", addr, err)
			}
			if srv == nil {
				t.Fatal("expected non-nil server")
			}
		})
	}
}

func TestGateway_Adversarial_SymlinkSocketRejected(t *testing.T) {
	tempDir, err := os.MkdirTemp("/tmp", "gw-sym")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	targetFile := filepath.Join(tempDir, "real_target.txt")
	if err := os.WriteFile(targetFile, []byte("target"), 0600); err != nil {
		t.Fatalf("failed to create target file: %v", err)
	}

	symlinkPath := filepath.Join(tempDir, "symlink.sock")
	if err := os.Symlink(targetFile, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	cfg := Config{
		SocketPath:  symlinkPath,
		UpstreamURL: "https://api.openai.com/v1",
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = srv.Start()
	if err == nil {
		_ = srv.Stop(context.Background())
		t.Fatal("expected Start() to reject symlink socket")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}

func TestGateway_HealthProbeBypass(t *testing.T) {
	cfg := Config{
		ListenAddr:  "127.0.0.1:0",
		UpstreamURL: "https://api.openai.com/v1",
		AuthToken:   "super-secret-client-token", // Auth token required for normal requests
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client := &http.Client{}

	for _, endpoint := range []string{"/health", "/healthz"} {
		req, err := http.NewRequest(http.MethodGet, srv.URL()+endpoint, nil)
		if err != nil {
			t.Fatalf("failed to create health request: %v", err)
		}
		// No auth header provided

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("health check failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK for %s without auth, got %d", endpoint, resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "shield-keyless") {
			t.Errorf("unexpected health response body: %s", string(body))
		}
	}
}

func TestGateway_UnixSocketListener(t *testing.T) {
	tempDir, err := os.MkdirTemp("/tmp", "gw-unx")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	sockPath := filepath.Join(tempDir, "gw.sock")

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	retriever := NewMockSecretRetriever(map[string][]byte{
		"openai/api-key": []byte("sk-test-socket-key"),
	})

	cfg := Config{
		SocketPath:      sockPath,
		UpstreamURL:     mockUpstream.URL,
		VaultSecret:     "openai/api-key",
		SecretRetriever: retriever,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	// Connect to unix socket directly with custom http.Transport
	udsClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
	}

	req, err := http.NewRequest(http.MethodPost, "http://localhost/v1/chat/completions", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := udsClient.Do(req)
	if err != nil {
		t.Fatalf("request over UDS failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK over UDS, got %d", resp.StatusCode)
	}
}

func TestGateway_Adversarial_MaxRequestBodyExceeded(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	retriever := NewMockSecretRetriever(map[string][]byte{
		"openai/api-key": []byte("sk-test-key"),
	})

	cfg := Config{
		ListenAddr:          "127.0.0.1:0",
		UpstreamURL:         mockUpstream.URL,
		VaultSecret:         "openai/api-key",
		MaxRequestBodyBytes: 1024, // 1 KiB limit
		SecretRetriever:     retriever,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	// Send 4 KiB payload, exceeding 1 KiB limit
	hugePayload := strings.Repeat("A", 4096)
	req, err := http.NewRequest(http.MethodPost, srv.URL()+"/v1/chat/completions", strings.NewReader(hugePayload))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should reject with 413 Request Entity Too Large or 502/bad request
	if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 413 or 502 for oversized request, got %d", resp.StatusCode)
	}
}
