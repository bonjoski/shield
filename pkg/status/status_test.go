package status

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadPID_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "shield.pid")

	currentPID := os.Getpid()
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", currentPID)), 0600); err != nil {
		t.Fatalf("failed to write pid file: %v", err)
	}

	pid, isAlive, isStale, err := ReadPID(pidFile)
	if err != nil {
		t.Fatalf("unexpected error reading valid PID: %v", err)
	}
	if pid != currentPID {
		t.Errorf("expected pid %d, got %d", currentPID, pid)
	}
	if !isAlive {
		t.Errorf("expected current process to be alive")
	}
	if isStale {
		t.Errorf("expected isStale to be false for live process")
	}
}

func TestReadPID_Stale(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "shield.pid")

	// 9999999 is almost certainly not running
	stalePID := 9999999
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", stalePID)), 0600); err != nil {
		t.Fatalf("failed to write pid file: %v", err)
	}

	pid, isAlive, isStale, err := ReadPID(pidFile)
	if err != nil {
		t.Fatalf("unexpected error reading stale PID: %v", err)
	}
	if pid != stalePID {
		t.Errorf("expected pid %d, got %d", stalePID, pid)
	}
	if isAlive {
		t.Errorf("expected stale pid %d to not be alive", stalePID)
	}
	if !isStale {
		t.Errorf("expected isStale to be true for dead process")
	}
}

func TestReadPID_NonExistent(t *testing.T) {
	_, _, _, err := ReadPID("/non/existent/path/shield.pid")
	if err == nil {
		t.Fatal("expected error for non-existent pid file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}

func TestReadPID_InvalidContent(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "shield.pid")

	if err := os.WriteFile(pidFile, []byte("not-a-number"), 0600); err != nil {
		t.Fatalf("failed to write pid file: %v", err)
	}

	_, _, _, err := ReadPID(pidFile)
	if err == nil {
		t.Fatal("expected error for non-numeric pid content")
	}
}

func TestReadPID_Symlink(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "real.pid")
	symlinkFile := filepath.Join(tmpDir, "symlink.pid")

	if err := os.WriteFile(targetFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600); err != nil {
		t.Fatalf("failed to write real pid file: %v", err)
	}
	if err := os.Symlink(targetFile, symlinkFile); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	_, _, _, err := ReadPID(symlinkFile)
	if err != ErrSymlinkDetected {
		t.Fatalf("expected ErrSymlinkDetected, got %v", err)
	}
}

func TestProbe_LiveHTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","shield":"active"}`))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind tcp listener: %v", err)
	}
	defer listener.Close()

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	defer func() { _ = srv.Close() }()

	addr := listener.Addr().String()

	info, err := Probe(context.Background(), Options{
		Addr:    addr,
		PIDFile: "/nonexistent.pid",
		Timeout: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}

	if !info.Running || !info.Healthy {
		t.Errorf("expected running and healthy, got running=%v, healthy=%v", info.Running, info.Healthy)
	}
	if info.Status != "online" {
		t.Errorf("expected status 'online', got %q", info.Status)
	}
	if info.Protocol != "http" {
		t.Errorf("expected protocol 'http', got %q", info.Protocol)
	}
	if info.ProbeResponse["shield"] != "active" {
		t.Errorf("expected probe response shield=active, got %v", info.ProbeResponse)
	}
}

func TestProbe_LiveHTTPS(t *testing.T) {
	tlsCert := generateSelfSignedCert(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","shield":"active"}`))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind tcp listener: %v", err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	defer tlsListener.Close()

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(tlsListener) }()
	defer func() { _ = srv.Close() }()

	addr := listener.Addr().String()

	info, err := Probe(context.Background(), Options{
		Addr:    addr,
		PIDFile: "/nonexistent.pid",
		Timeout: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}

	if !info.Running || !info.Healthy {
		t.Errorf("expected running and healthy, got running=%v, healthy=%v", info.Running, info.Healthy)
	}
	if info.Status != "online" {
		t.Errorf("expected status 'online', got %q", info.Status)
	}
	if info.Protocol != "https" {
		t.Errorf("expected protocol 'https', got %q", info.Protocol)
	}
}

func TestProbe_LiveUnixSocket(t *testing.T) {
	// On macOS, unix domain socket path must not exceed 104 bytes (sizeof sun_path).
	tmpDir, err := os.MkdirTemp("/tmp", "shld-stat-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	sockPath := filepath.Join(tmpDir, "shield.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	defer l.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","shield":"active"}`))
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()

	info, err := Probe(context.Background(), Options{
		SocketPath: sockPath,
		PIDFile:    "/nonexistent.pid",
		Timeout:    1 * time.Second,
	})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}

	if !info.Running || !info.Healthy {
		t.Errorf("expected running and healthy, got running=%v, healthy=%v", info.Running, info.Healthy)
	}
	if info.Protocol != "unix" {
		t.Errorf("expected protocol 'unix', got %q", info.Protocol)
	}
}

func TestProbe_Offline(t *testing.T) {
	info, err := Probe(context.Background(), Options{
		Addr:    "127.0.0.1:59999", // Unused port
		PIDFile: "/nonexistent.pid",
		Timeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("probe returned unexpected error: %v", err)
	}

	if info.Running || info.Healthy {
		t.Errorf("expected running=false, healthy=false, got running=%v, healthy=%v", info.Running, info.Healthy)
	}
	if info.Status != "offline" {
		t.Errorf("expected status 'offline', got %q", info.Status)
	}
	if !strings.Contains(info.Error, "Shield proxy is not running") {
		t.Errorf("expected informative error message, got: %s", info.Error)
	}
}

func TestProbe_Degraded(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "shield.pid")

	// Write current live PID
	currentPID := os.Getpid()
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", currentPID)), 0600); err != nil {
		t.Fatalf("failed to write pid file: %v", err)
	}

	// Probe offline port
	info, err := Probe(context.Background(), Options{
		Addr:    "127.0.0.1:59998",
		PIDFile: pidFile,
		Timeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("probe returned unexpected error: %v", err)
	}

	if !info.Running {
		t.Errorf("expected running=true due to live PID")
	}
	if info.Healthy {
		t.Errorf("expected healthy=false due to probe failure")
	}
	if info.Status != "degraded" {
		t.Errorf("expected status 'degraded', got %q", info.Status)
	}
	if info.PID != currentPID {
		t.Errorf("expected pid %d, got %d", currentPID, info.PID)
	}
	if !info.PIDRunning {
		t.Errorf("expected PIDRunning to be true")
	}
}

func TestFormatHumanAndJSON(t *testing.T) {
	info := &Info{
		Running:       true,
		Healthy:       true,
		Status:        "online",
		ListeningAddr: "https://127.0.0.1:8443",
		Protocol:      "https",
		PID:           12345,
		PIDRunning:    true,
		Uptime:        "01:23:45",
		Version:       "v0.2.0",
		ProbeResponse: map[string]string{
			"status": "healthy",
			"shield": "active",
		},
	}

	human := info.FormatHuman()
	if !strings.Contains(human, "Shield Proxy Status: ONLINE") {
		t.Errorf("expected header in human format, got:\n%s", human)
	}
	if !strings.Contains(human, "127.0.0.1:8443") {
		t.Errorf("expected listening address in human format, got:\n%s", human)
	}

	jsonStr, err := info.FormatJSON()
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if parsed["status"] != "online" {
		t.Errorf("expected json status 'online', got %v", parsed["status"])
	}
	if parsed["pid"] != float64(12345) {
		t.Errorf("expected json pid 12345, got %v", parsed["pid"])
	}
}

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Shield Status Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse tls keypair: %v", err)
	}
	return tlsCert
}
