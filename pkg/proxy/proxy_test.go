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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/shield"
)

func TestProxyEndToEnd(t *testing.T) {
	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "Refactored code without secrets.")
	mock.SetReply("[SECRET_REF_", "Refactored code using [SECRET_REF_")

	srv := NewServer("127.0.0.1:0", engine, mock)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer srv.Stop(context.Background())

	addr := srv.ListenerAddr().String()

	reqPayload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": "Please review this key: AKIAIOSFODNN7EXAMPLE",
			},
		},
	}
	body, _ := json.Marshal(reqPayload)

	resp, err := http.Post("http://"+addr+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to call proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, string(respBytes))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&parsed)

	if len(parsed.Choices) == 0 {
		t.Fatalf("expected at least 1 choice in response")
	}

	if mock.CallCount() != 1 {
		t.Errorf("expected mock provider to be called once, got %d", mock.CallCount())
	}
}

func TestProxyUnixSocketEndToEnd(t *testing.T) {
	// On macOS, unix domain socket path must not exceed 104 bytes (sizeof sun_path).
	// t.TempDir() in /var/folders/... often exceeds 104 chars, so we use /tmp for socket tests.
	tmpDir, err := os.MkdirTemp("/tmp", "shld-sock-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	sockPath := filepath.Join(tmpDir, "shield.sock")

	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "Unix socket response.")

	srv := NewServerWithOptions(Options{
		SocketPath: sockPath,
	}, engine, mock)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start socket proxy: %v", err)
	}

	// Verify socket file permissions: must be 0600
	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("socket file not found: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("expected socket permissions 0600, got %o", perm)
	}

	// Client connecting via Unix domain socket
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
	}

	// 1. Check healthz
	resp, err := client.Get("http://unix/healthz")
	if err != nil {
		t.Fatalf("failed GET /healthz over unix socket: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// 2. Stop server and verify socket cleanup
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop server: %v", err)
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("expected socket file to be deleted on Stop(), but it still exists")
	}
}

func TestProxyHTTPSEndToEnd(t *testing.T) {
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
	mock := provider.NewMockProvider("mock-ai", "HTTPS encrypted response.")

	srv := NewServerWithOptions(Options{
		Addr:     "127.0.0.1:0",
		TLS:      true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}, engine, mock)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start HTTPS proxy: %v", err)
	}
	defer srv.Stop(context.Background())

	addr := srv.ListenerAddr().String()

	// Client trusting our CA
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}

	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("HTTPS GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
}

func TestProxyPostQuantumMLKEMKeyExchange(t *testing.T) {
	tempDir := t.TempDir()
	caCertPEM, caKeyPEM := generateTestCA(t)
	serverCertPEM, serverKeyPEM := generateTestCert(t, caCertPEM, caKeyPEM, true, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	_ = os.WriteFile(certFile, serverCertPEM, 0600)
	_ = os.WriteFile(keyFile, serverKeyPEM, 0600)

	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "OK")

	srv := NewServerWithOptions(Options{
		Addr:     "127.0.0.1:0",
		TLS:      true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}, engine, mock)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop(context.Background())

	addr := srv.ListenerAddr().String()
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	// Connect using tls.Dial to inspect the negotiated TLS connection state
	tlsConfig := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		t.Fatalf("failed tls.Dial: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	t.Logf("Negotiated TLS Version: 0x%04x", state.Version)
	t.Logf("Negotiated Curve / Key Exchange: %s (CurveID %d)", state.CurveID, state.CurveID)

	if state.CurveID != tls.X25519MLKEM768 {
		t.Errorf("expected post-quantum hybrid X25519MLKEM768 (%d), got: %s (%d)", tls.X25519MLKEM768, state.CurveID, state.CurveID)
	}
}

func TestProxyMTLSEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	caCertPEM, caKeyPEM := generateTestCA(t)
	serverCertPEM, serverKeyPEM := generateTestCert(t, caCertPEM, caKeyPEM, true, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	clientCertPEM, clientKeyPEM := generateTestCert(t, caCertPEM, caKeyPEM, false, nil, nil)

	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	caFile := filepath.Join(tempDir, "ca.crt")

	_ = os.WriteFile(certFile, serverCertPEM, 0600)
	_ = os.WriteFile(keyFile, serverKeyPEM, 0600)
	_ = os.WriteFile(caFile, caCertPEM, 0644)

	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "mTLS response.")

	srv := NewServerWithOptions(Options{
		Addr:     "127.0.0.1:0",
		TLS:      true,
		CertFile: certFile,
		KeyFile:  keyFile,
		ClientCA: caFile,
	}, engine, mock)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start mTLS server: %v", err)
	}
	defer srv.Stop(context.Background())

	addr := srv.ListenerAddr().String()
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	clientTLSCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("failed to load client keypair: %v", err)
	}

	// 1. Client with valid mTLS certificate
	validClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientTLSCert},
			},
		},
	}

	resp, err := validClient.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("valid mTLS request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	// 2. Client WITHOUT certificate must be rejected
	unauthClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}

	_, err = unauthClient.Get("https://" + addr + "/healthz")
	if err == nil {
		t.Fatalf("expected unauthenticated client connection to fail mTLS, but it succeeded")
	}
}

// Helpers for ephemeral test certificates
func generateTestCA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Shield Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM
}

func generateTestCert(t *testing.T, caCertPEM, caKeyPEM []byte, isServer bool, dnsNames []string, ips []net.IP) ([]byte, []byte) {
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
			CommonName: "Shield Test Cert",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
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
