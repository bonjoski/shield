package adversarial

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/shield/pkg/status"
)

// ADV-STAT-E2E-01: End-to-End Status Probe Against Mock Loopback
func TestADV_StatusEndToEndProbe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","shield":"active"}`))
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()

	addr := l.Addr().String()

	info, err := status.Probe(context.Background(), status.Options{
		Addr:    addr,
		PIDFile: "/nonexistent.pid",
		Timeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}

	if !info.Healthy || info.Status != "online" {
		t.Errorf("expected online status, got %+v", info)
	}

	human := info.FormatHuman()
	if !strings.Contains(human, "Shield Proxy Status: ONLINE") {
		t.Errorf("expected ONLINE in formatted output: %s", human)
	}

	jsonStr, err := info.FormatJSON()
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}
	if !strings.Contains(jsonStr, `"status": "online"`) {
		t.Errorf("expected status: online in JSON: %s", jsonStr)
	}
}

// ADV-STAT-E2E-02: Offline Degraded Fallback Verification
func TestADV_StatusOfflineReport(t *testing.T) {
	info, err := status.Probe(context.Background(), status.Options{
		Addr:    "127.0.0.1:59997",
		PIDFile: "/nonexistent.pid",
		Timeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("unexpected probe error: %v", err)
	}

	if info.Healthy || info.Status != "offline" {
		t.Errorf("expected offline status, got %+v", info)
	}

	human := info.FormatHuman()
	if !strings.Contains(human, "OFFLINE") {
		t.Errorf("expected OFFLINE in formatted output: %s", human)
	}
	if !strings.Contains(human, "Shield proxy is not running") {
		t.Errorf("expected informative offline message: %s", human)
	}
}

// ADV-STAT-E2E-03: Symlink Attack on PID File Detection
func TestADV_StatusSymlinkPIDFileRejection(t *testing.T) {
	tmpDir := t.TempDir()
	realFile := filepath.Join(tmpDir, "real.pid")
	symlinkFile := filepath.Join(tmpDir, "shield.pid")

	_ = os.WriteFile(realFile, []byte("9999999"), 0600)
	if err := os.Symlink(realFile, symlinkFile); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	info, err := status.Probe(context.Background(), status.Options{
		Addr:    "127.0.0.1:59996",
		PIDFile: symlinkFile,
		Timeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("unexpected probe error: %v", err)
	}

	if info.PIDRunning {
		t.Errorf("expected PIDRunning to be false on symlinked PID file")
	}
	if !strings.Contains(info.Error, "symlink") {
		t.Errorf("expected symlink warning in info.Error: %q", info.Error)
	}
}
