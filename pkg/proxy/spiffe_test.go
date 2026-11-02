package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/shield"
)

func generateTestCertWithURIs(t *testing.T, caCertPEM, caKeyPEM []byte, isServer bool, dnsNames []string, ips []net.IP, uris []*url.URL) ([]byte, []byte) {
	t.Helper()

	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Shield SPIFFE Test Cert",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		URIs:      uris,
	}

	if isServer {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = dnsNames
		tmpl.IPAddresses = ips
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalECPrivateKey(certKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM
}

func TestMatchSPIFFEID(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		patterns []string
		expected bool
	}{
		{
			name:     "exact match success",
			clientID: "spiffe://bonjoski.local/ns/dev/sa/payment-api",
			patterns: []string{"spiffe://bonjoski.local/ns/dev/sa/payment-api"},
			expected: true,
		},
		{
			name:     "exact match mismatch",
			clientID: "spiffe://bonjoski.local/ns/dev/sa/auth-api",
			patterns: []string{"spiffe://bonjoski.local/ns/dev/sa/payment-api"},
			expected: false,
		},
		{
			name:     "wildcard prefix success",
			clientID: "spiffe://bonjoski.local/ns/dev/sa/payment-api",
			patterns: []string{"spiffe://bonjoski.local/ns/dev/*"},
			expected: true,
		},
		{
			name:     "wildcard prefix mismatch",
			clientID: "spiffe://bonjoski.local/ns/prod/sa/payment-api",
			patterns: []string{"spiffe://bonjoski.local/ns/dev/*"},
			expected: false,
		},
		{
			name:     "wildcard prefix partial word boundary prevents spoofing",
			clientID: "spiffe://bonjoski.local/ns/dev-evil/sa/app",
			patterns: []string{"spiffe://bonjoski.local/ns/dev/*"},
			expected: false,
		},
		{
			name:     "multiple patterns first matches",
			clientID: "spiffe://bonjoski.local/ns/dev/sa/app1",
			patterns: []string{"spiffe://bonjoski.local/ns/dev/*", "spiffe://bonjoski.local/ns/prod/*"},
			expected: true,
		},
		{
			name:     "multiple patterns second matches",
			clientID: "spiffe://bonjoski.local/ns/prod/sa/app2",
			patterns: []string{"spiffe://bonjoski.local/ns/dev/*", "spiffe://bonjoski.local/ns/prod/*"},
			expected: true,
		},
		{
			name:     "global wildcard matches any",
			clientID: "spiffe://bonjoski.local/ns/custom/sa/worker",
			patterns: []string{"*"},
			expected: true,
		},
		{
			name:     "empty patterns list",
			clientID: "spiffe://bonjoski.local/ns/dev/sa/app",
			patterns: []string{},
			expected: false,
		},
		{
			name:     "whitespace in patterns is trimmed",
			clientID: "spiffe://bonjoski.local/ns/dev/sa/app",
			patterns: []string{"  spiffe://bonjoski.local/ns/dev/*  "},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchSPIFFEID(tc.clientID, tc.patterns)
			if got != tc.expected {
				t.Errorf("matchSPIFFEID(%q, %v) = %v; want %v", tc.clientID, tc.patterns, got, tc.expected)
			}
		})
	}
}

func setupSPIFFETestServer(t *testing.T, allowedSPIFFEIDs []string) (*Server, string, *x509.CertPool, []byte, []byte) {
	t.Helper()
	tempDir := t.TempDir()
	caCertPEM, caKeyPEM := generateTestCA(t)
	serverCertPEM, serverKeyPEM := generateTestCert(t, caCertPEM, caKeyPEM, true, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	caFile := filepath.Join(tempDir, "ca.crt")

	if err := os.WriteFile(certFile, serverCertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, serverKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, caCertPEM, 0644); err != nil {
		t.Fatal(err)
	}

	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "SPIFFE authorized response.")

	srv := NewServerWithOptions(Options{
		Addr:             "127.0.0.1:0",
		TLS:              true,
		CertFile:         certFile,
		KeyFile:          keyFile,
		ClientCA:         caFile,
		AllowedSPIFFEIDs: allowedSPIFFEIDs,
	}, engine, mock)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	return srv, srv.ListenerAddr().String(), caPool, caCertPEM, caKeyPEM
}

func makeChatRequest(t *testing.T, client *http.Client, addr string) (*http.Response, map[string]interface{}) {
	t.Helper()
	reqPayload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": "Hello from SPIFFE client",
			},
		},
	}
	body, _ := json.Marshal(reqPayload)

	resp, err := client.Post("https://"+addr+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	respBytes, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var parsed map[string]interface{}
	_ = json.Unmarshal(respBytes, &parsed)
	return resp, parsed
}

func TestSPIFFE_AuthorizedExactMatch(t *testing.T) {
	spiffeID := "spiffe://bonjoski.local/ns/dev/sa/payment-api"
	srv, addr, caPool, caCertPEM, caKeyPEM := setupSPIFFETestServer(t, []string{spiffeID})
	defer srv.Stop(context.Background())

	spiffeURL, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}

	clientCertPEM, clientKeyPEM := generateTestCertWithURIs(t, caCertPEM, caKeyPEM, false, nil, nil, []*url.URL{spiffeURL})
	clientTLSCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientTLSCert},
			},
		},
	}

	resp, body := makeChatRequest(t, client, addr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %v", resp.StatusCode, body)
	}

	if choices, ok := body["choices"].([]interface{}); !ok || len(choices) == 0 {
		t.Errorf("expected choices in response, got %v", body)
	}
}

func TestSPIFFE_AuthorizedWildcardPrefix(t *testing.T) {
	pattern := "spiffe://bonjoski.local/ns/dev/*"
	srv, addr, caPool, caCertPEM, caKeyPEM := setupSPIFFETestServer(t, []string{pattern})
	defer srv.Stop(context.Background())

	spiffeURL, err := url.Parse("spiffe://bonjoski.local/ns/dev/sa/order-service")
	if err != nil {
		t.Fatal(err)
	}

	clientCertPEM, clientKeyPEM := generateTestCertWithURIs(t, caCertPEM, caKeyPEM, false, nil, nil, []*url.URL{spiffeURL})
	clientTLSCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientTLSCert},
			},
		},
	}

	resp, body := makeChatRequest(t, client, addr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK with wildcard match, got %d: %v", resp.StatusCode, body)
	}
}

func TestSPIFFE_UnauthorizedValidSVIDNotInACL(t *testing.T) {
	pattern := "spiffe://bonjoski.local/ns/dev/*"
	srv, addr, caPool, caCertPEM, caKeyPEM := setupSPIFFETestServer(t, []string{pattern})
	defer srv.Stop(context.Background())

	unauthorizedSVID := "spiffe://bonjoski.local/ns/prod/sa/payment-api"
	spiffeURL, err := url.Parse(unauthorizedSVID)
	if err != nil {
		t.Fatal(err)
	}

	clientCertPEM, clientKeyPEM := generateTestCertWithURIs(t, caCertPEM, caKeyPEM, false, nil, nil, []*url.URL{spiffeURL})
	clientTLSCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientTLSCert},
			},
		},
	}

	resp, body := makeChatRequest(t, client, addr)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d: %v", resp.StatusCode, body)
	}

	if body["error"] != "unauthorized spiffe id" {
		t.Errorf("expected error 'unauthorized spiffe id', got %v", body["error"])
	}
	if body["spiffe_id"] != unauthorizedSVID {
		t.Errorf("expected spiffe_id %q, got %v", unauthorizedSVID, body["spiffe_id"])
	}
}

func TestSPIFFE_ClientWithoutSPIFFEURISAN(t *testing.T) {
	pattern := "spiffe://bonjoski.local/ns/dev/*"
	srv, addr, caPool, caCertPEM, caKeyPEM := setupSPIFFETestServer(t, []string{pattern})
	defer srv.Stop(context.Background())

	// Certificate without any URI SANs
	clientCertPEM, clientKeyPEM := generateTestCert(t, caCertPEM, caKeyPEM, false, nil, nil)
	clientTLSCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientTLSCert},
			},
		},
	}

	resp, body := makeChatRequest(t, client, addr)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d: %v", resp.StatusCode, body)
	}

	if body["error"] != "spiffe uri san required" {
		t.Errorf("expected error 'spiffe uri san required', got %v", body["error"])
	}
}

func TestSPIFFE_ClientWithoutCertificate(t *testing.T) {
	tempDir := t.TempDir()
	caCertPEM, caKeyPEM := generateTestCA(t)
	serverCertPEM, serverKeyPEM := generateTestCert(t, caCertPEM, caKeyPEM, true, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	_ = os.WriteFile(certFile, serverCertPEM, 0600)
	_ = os.WriteFile(keyFile, serverKeyPEM, 0600)

	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "OK")

	// Server with AllowedSPIFFEIDs and TLS, but no ClientCA (ClientAuth = RequestClientCert)
	srv := NewServerWithOptions(Options{
		Addr:             "127.0.0.1:0",
		TLS:              true,
		CertFile:         certFile,
		KeyFile:          keyFile,
		AllowedSPIFFEIDs: []string{"spiffe://bonjoski.local/ns/dev/*"},
	}, engine, mock)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop(context.Background())

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	// Client without certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}

	resp, body := makeChatRequest(t, client, srv.ListenerAddr().String())
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d: %v", resp.StatusCode, body)
	}

	if body["error"] != "client certificate required" {
		t.Errorf("expected error 'client certificate required', got %v", body["error"])
	}
}

func TestSPIFFE_PlaintextWithoutTLS(t *testing.T) {
	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "OK")

	srv := NewServerWithOptions(Options{
		AllowedSPIFFEIDs: []string{"spiffe://bonjoski.local/ns/dev/*"},
	}, engine, mock)

	handler := srv.AuthorizeSPIFFE(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte("{}")))
	// req.TLS is nil

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", rec.Code)
	}

	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "client certificate required" {
		t.Errorf("expected error 'client certificate required', got %q", body["error"])
	}
}
