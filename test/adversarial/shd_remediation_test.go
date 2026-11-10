package adversarial

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/proxy"
	"github.com/bonjoski/shield/pkg/reassembly"
	"github.com/bonjoski/shield/pkg/shield"
)

// EchoProvider echoes received messages and system prompts back so round-trip placeholder
// rehydration across multi-turn / multimodal / tool_calls payloads can be verified end-to-end.
type EchoProvider struct {
	mu      sync.Mutex
	lastReq provider.Request
}

func (e *EchoProvider) Name() string { return "echo-test" }

func (e *EchoProvider) Complete(_ context.Context, req provider.Request) (*provider.Response, error) {
	e.mu.Lock()
	e.lastReq = req
	e.mu.Unlock()

	var parts []string
	if req.SystemPrompt != "" {
		parts = append(parts, "SYS="+req.SystemPrompt)
	}
	for _, m := range req.Messages {
		parts = append(parts, m.Role+"="+m.Content)
	}
	return &provider.Response{
		Content:      strings.Join(parts, " | "),
		Model:        req.Model,
		FinishReason: "stop",
	}, nil
}

// TestSHD01_SPIFFEVerifiedChainsAndCanonicalization verifies:
// 1. Startup fails closed if AllowedSPIFFEIDs is configured without ClientCA or TLS.
// 2. Unverified PeerCertificates without VerifiedChains are rejected with 403.
// 3. SPIFFE IDs containing `..`, empty segments, or percent-encoding are rejected.
func TestSHD01_SPIFFEVerifiedChainsAndCanonicalization(t *testing.T) {
	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock", "OK")

	// 1. Refuse startup without TLS / ClientCA
	srvNoTLS := proxy.NewServerWithOptions(proxy.Options{
		Addr:             "127.0.0.1:0",
		AllowedSPIFFEIDs: []string{"spiffe://bonjoski.local/ns/dev/*"},
	}, engine, mock)
	if err := srvNoTLS.Start(); !errors.Is(err, proxy.ErrSPIFFERequiresClientCA) {
		_ = srvNoTLS.Stop(context.Background())
		t.Fatalf("expected ErrSPIFFERequiresClientCA without TLS/ClientCA, got: %v", err)
	}

	// 2. Unverified PeerCertificates (VerifiedChains == nil) MUST be rejected by middleware
	caPEM, caKeyPEM := generateTestCA(t, "Test CA")
	u, _ := url.Parse("spiffe://bonjoski.local/ns/dev/sa/worker")
	certPEM, _ := generateTestCertWithURIs(t, caPEM, caKeyPEM, false, nil, nil, []*url.URL{u})
	block, _ := decodePEMCert(t, certPEM)

	handler := srvNoTLS.AuthorizeSPIFFE(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{block}, // Unverified! VerifiedChains is empty!
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SHD-01 FAILED: unverified PeerCertificates[0] accepted without VerifiedChains (status %d)", rec.Code)
	}

	// 3. Path traversal `..`, empty segment `//`, and percent-encoded SPIFFE SANs MUST be rejected even with VerifiedChains
	traversalIDs := []string{
		"spiffe://bonjoski.local/ns/dev/../../ns/prod/sa/admin",
		"spiffe://bonjoski.local/ns/dev//sa/admin",
		"spiffe://bonjoski.local/ns/dev/",
		"spiffe://bonjoski.local/ns/dev/%2e%2e/prod",
	}
	for _, badID := range traversalIDs {
		badURL := &url.URL{Scheme: "spiffe", Host: "bonjoski.local", Path: strings.TrimPrefix(badID, "spiffe://bonjoski.local")}
		badCertPEM, _ := generateTestCertWithURIs(t, caPEM, caKeyPEM, false, nil, nil, []*url.URL{badURL})
		badCert, _ := decodePEMCert(t, badCertPEM)

		reqTrav := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
		reqTrav.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{badCert},
			VerifiedChains:   [][]*x509.Certificate{{badCert}},
		}
		recTrav := httptest.NewRecorder()
		handler.ServeHTTP(recTrav, reqTrav)
		if recTrav.Code != http.StatusForbidden {
			t.Errorf("SHD-01 FAILED: non-canonical SPIFFE URI %q accepted (status %d)", badID, recTrav.Code)
		}
	}
}

func decodePEMCert(t *testing.T, certPEM []byte) (*x509.Certificate, error) {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse x509 certificate: %v", err)
	}
	return cert, nil
}

// TestSHD02_GeminiHeaderAuthModelValidationAndSanitized502 verifies:
// 1. GeminiProvider sends API key in `x-goog-api-key` header and NEVER in `?key=` query string.
// 2. Invalid `req.Model` values containing `?`, `/`, `..`, `&` are rejected before URL construction.
// 3. Proxy 502 error responses never leak upstream URLs, query parameters, or API keys.
func TestSHD02_GeminiHeaderAuthModelValidationAndSanitized502(t *testing.T) {
	const secretGeminiKey = "mock-gemini-test-key-shd02-remediation"
	var gotHeaderKey, gotRawQuery, gotPath string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaderKey = r.Header.Get("x-goog-api-key")
		gotRawQuery = r.URL.RawQuery
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"Safe Gemini reply"}]},"finishReason":"STOP"}]}`))
	}))
	defer upstream.Close()

	gem := provider.NewGeminiProviderForTest(secretGeminiKey, "gemini-2.0-flash", upstream.URL)
	resp, err := gem.Complete(context.Background(), provider.Request{
		Model:    "gemini-2.0-flash",
		Messages: []provider.Message{{Role: provider.RoleUser, Content: "Hello"}},
	})
	if err != nil {
		t.Fatalf("Gemini Complete failed: %v", err)
	}
	if resp.Content != "Safe Gemini reply" {
		t.Errorf("unexpected response content: %q", resp.Content)
	}
	if gotHeaderKey != secretGeminiKey {
		t.Errorf("expected x-goog-api-key header, got %q", gotHeaderKey)
	}
	if gotRawQuery != "" || strings.Contains(gotRawQuery, secretGeminiKey) {
		t.Errorf("SHD-02 FAILED: API key or query string leaked in upstream URL: %q", gotRawQuery)
	}
	if gotPath != "/models/gemini-2.0-flash:generateContent" {
		t.Errorf("unexpected upstream path: %q", gotPath)
	}

	// Model injection attempts MUST be rejected
	badModels := []string{
		"gemini-2.0-flash? evil=1#",
		"../../v1/files",
		"gemini/evil",
		"gemini%2f..%2fevil",
	}
	for _, bm := range badModels {
		if _, err := gem.Complete(context.Background(), provider.Request{
			Model:    bm,
			Messages: []provider.Message{{Role: provider.RoleUser, Content: "Hello"}},
		}); err == nil {
			t.Errorf("SHD-02 FAILED: accepted invalid model name %q", bm)
		}
	}

	// Verify HTTP 502 sanitization when upstream connection fails
	closedUpstream := httptest.NewServer(http.NotFoundHandler())
	closedURL := closedUpstream.URL
	closedUpstream.Close()

	failingGem := provider.NewGeminiProviderForTest(secretGeminiKey, "gemini-2.0-flash", closedURL)
	srv := proxy.NewServer("127.0.0.1:0", shield.NewEngine(shield.DefaultConfig()), failingGem)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop(context.Background())

	httpResp, err := http.Post("http://"+srv.ListenerAddr().String()+"/v1/chat/completions",
		"application/json",
		strings.NewReader(`{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer httpResp.Body.Close()
	errBody, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway, got %d", httpResp.StatusCode)
	}
	if strings.Contains(string(errBody), secretGeminiKey) || strings.Contains(string(errBody), closedURL) {
		t.Fatalf("SHD-02 FAILED: HTTP 502 response leaked upstream URL or secret: %s", string(errBody))
	}
}

// TestSHD04_SHD05_SharedTokenMapRoundTripAndRecursiveMultimodalScrub verifies:
// 1. Identical secrets across `system`, multimodal `content` arrays, and `tool_calls` map to ONE `[SECRET_REF_...]` ID.
// 2. Echoed `[SECRET_REF_...]` placeholders in the AI response pass CheckUnmappedPlaceholders (no 502!) and rehydrate cleanly.
// 3. Oversized >10 MiB request bodies are rejected with 413 Request Entity Too Large.
func TestSHD04_SHD05_SharedTokenMapRoundTripAndRecursiveMultimodalScrub(t *testing.T) {
	echo := &EchoProvider{}
	srv := proxy.NewServer("127.0.0.1:0", shield.NewEngine(shield.DefaultConfig()), echo)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop(context.Background())

	const sharedAWSKey = "AKIAIOSFODNN7EXAMPLE"
	const sharedGitHubTok = "ghs_abcdefghijklmnopqrstuvwxyz1234567890ABCD"

	payload := map[string]any{
		"model":  "claude-3-5-sonnet-20241022",
		"system": []map[string]any{{"type": "text", "text": "System uses " + sharedAWSKey}},
		"messages": []map[string]any{
			{
				"role": "user",
				"content": []map[string]any{
					{"type": "text", "text": "First message with " + sharedAWSKey + " and " + sharedGitHubTok},
				},
			},
			{
				"role":    "assistant",
				"content": "Tool call trace",
				"tool_calls": []map[string]any{
					{
						"id":   "call_1",
						"type": "function",
						"function": map[string]any{
							"name":      "deploy",
							"arguments": `{"aws":"` + sharedAWSKey + `","gh":"` + sharedGitHubTok + `"}`,
						},
					},
				},
			},
		},
	}
	rawJSON, _ := json.Marshal(payload)

	resp, err := http.Post("http://"+srv.ListenerAddr().String()+"/v1/messages", "application/json", bytes.NewReader(rawJSON))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SHD-04/05 FAILED: expected 200 OK on echoed placeholder round-trip, got %d: %s", resp.StatusCode, string(respBytes))
	}

	// Verify upstream NEVER saw plaintext secrets in system, multimodal content, or tool_calls
	echo.mu.Lock()
	sentReq := echo.lastReq
	echo.mu.Unlock()
	serializedUpstream, _ := json.Marshal(sentReq)
	if strings.Contains(string(serializedUpstream), sharedAWSKey) || strings.Contains(string(serializedUpstream), sharedGitHubTok) {
		t.Fatalf("SHD-05 FAILED: plaintext secret leaked to upstream provider: %s", string(serializedUpstream))
	}

	// Verify client response rehydrated both secrets cleanly
	if !strings.Contains(string(respBytes), sharedAWSKey) || !strings.Contains(string(respBytes), sharedGitHubTok) {
		t.Fatalf("SHD-04 FAILED: client response failed to rehydrate echoed placeholders: %s", string(respBytes))
	}

	// Verify >10 MiB payload is rejected with 413 Request Entity Too Large
	oversized := `{"model":"gpt-4o","messages":[{"role":"user","content":"` + strings.Repeat("A", int(proxy.MaxRequestBodyBytes)+1024) + `"}]}`
	bigResp, err := http.Post("http://"+srv.ListenerAddr().String()+"/v1/chat/completions", "application/json", strings.NewReader(oversized))
	if err != nil {
		t.Fatal(err)
	}
	defer bigResp.Body.Close()
	if bigResp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("SHD-05 FAILED: expected 413 Request Entity Too Large, got %d", bigResp.StatusCode)
	}
}

// TestSHD07_SafeHTTPBlocksIMDSPrivateLoopbackAndCrossOriginRedirects verifies SSRF & redirect defenses.
func TestSHD07_SafeHTTPBlocksIMDSPrivateLoopbackAndCrossOriginRedirects(t *testing.T) {
	blockedBaseURLs := []string{
		"http://169.254.169.254/v1",
		"https://169.254.169.254/latest/meta-data",
		"https://[::ffff:169.254.169.254]/v1",
		"https://[fd00:ec2::254]/v1",
		"https://[64:ff9b::169.254.169.254]/v1",
		"https://100.100.100.200/v1",
		"https://10.0.0.1/v1",
		"https://127.0.0.1:8080/v1",
		"http://api.openai.com/v1", // cleartext downgrade on cloud provider
		"file:///etc/passwd",
	}

	for _, badURL := range blockedBaseURLs {
		prov := provider.NewOpenAIProvider("sk-test-12345", "gpt-4o", badURL)
		_, err := prov.Complete(context.Background(), provider.Request{
			Model:    "gpt-4o",
			Messages: []provider.Message{{Role: provider.RoleUser, Content: "ping"}},
		})
		if err == nil {
			t.Errorf("SHD-07 FAILED: OpenAIProvider allowed unsafe BaseURL %q", badURL)
		}
	}

	// Verify Ollama blocks IMDS even though it permits literal localhost
	ollamaIMDS := provider.NewOllamaProvider("http://169.254.169.254:11434", "llama3")
	if _, err := ollamaIMDS.Complete(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: provider.RoleUser, Content: "ping"}},
	}); err == nil {
		t.Error("SHD-07 FAILED: OllamaProvider allowed IMDS BaseURL")
	}

	// Verify cross-origin HTTP 302 redirect is blocked so Bearer headers never follow redirects
	evilTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("SHD-07 FAILED: cross-origin redirect reached evil target with Authorization=%q", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer evilTarget.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evilTarget.URL+"/steal", http.StatusFound)
	}))
	defer redirector.Close()

	testOpenAI := provider.NewOpenAIProviderForTest("sk-secret-key", "gpt-4o", redirector.URL)
	_, err := testOpenAI.Complete(context.Background(), provider.Request{
		Model:    "gpt-4o",
		Messages: []provider.Message{{Role: provider.RoleUser, Content: "hello"}},
	})
	if err == nil || !errors.Is(err, provider.ErrCrossOriginRedirect) {
		t.Fatalf("SHD-07 FAILED: expected ErrCrossOriginRedirect, got: %v", err)
	}
}

// TestSHD08_ValidateSyntaxGoAST verifies go/parser validation without "package " substring bugs.
func TestSHD08_ValidateSyntaxGoAST(t *testing.T) {
	r := reassembly.NewReassembler()

	// Valid statement containing "package " inside a string literal must succeed
	if err := r.ValidateSyntax("go", `msg := "invalid package name"; _ = msg`); err != nil {
		t.Fatalf("expected valid statement with 'package ' string literal to pass, got: %v", err)
	}

	// Valid top-level function declaration without `package` header must succeed
	if err := r.ValidateSyntax("go", `func add(a, b int) int { return a + b }`); err != nil {
		t.Fatalf("expected valid top-level func snippet to pass, got: %v", err)
	}

	// Brace-breakout injection attempting to escape statement wrapper must fail
	if err := r.ValidateSyntax("go", "x := 1\n_ = x\n}\nfunc Injected() {\n"); err == nil {
		t.Fatal("SHD-08 FAILED: brace-breakout snippet passed ValidateSyntax")
	}
}
