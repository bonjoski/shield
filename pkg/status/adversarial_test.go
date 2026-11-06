package status

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ADV-STAT-01: Symlink Traversal Protection on PID File
// Attack Vector: Adversary symlinks ~/.shield/shield.pid to /etc/hosts or arbitrary file
// Defense: Probe checks os.Lstat and rejects symlink files.
func TestADV_PIDFileSymlinkTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "target.txt")
	symlinkPath := filepath.Join(tmpDir, "shield.pid")

	if err := os.WriteFile(targetFile, []byte("12345"), 0644); err != nil {
		t.Fatalf("failed to create target file: %v", err)
	}
	if err := os.Symlink(targetFile, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	_, _, _, err := ReadPID(symlinkPath)
	if err != ErrSymlinkDetected {
		t.Fatalf("ADV-STAT-01 FAILED: Expected ErrSymlinkDetected on symlink PID file, got %v", err)
	}

	info, err := Probe(context.Background(), Options{
		Addr:    "127.0.0.1:59999",
		PIDFile: symlinkPath,
		Timeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}

	if info.PIDRunning {
		t.Errorf("ADV-STAT-01 FAILED: Symlinked PID file must not be treated as running")
	}
	if !strings.Contains(info.Error, "symlink") {
		t.Errorf("ADV-STAT-01 FAILED: Expected warning about symlink in info.Error, got %q", info.Error)
	}
}

// ADV-STAT-02: Denial of Service via Huge PID File
// Attack Vector: Adversary writes 10MB of garbage into ~/.shield/shield.pid to trigger memory exhaustion.
// Defense: ReadPID bounds reading to 64 bytes via io.LimitReader.
func TestADV_PIDFileHugePayloadDoS(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "huge.pid")

	hugePayload := strings.Repeat("A", 10*1024*1024) // 10MB
	if err := os.WriteFile(pidFile, []byte(hugePayload), 0600); err != nil {
		t.Fatalf("failed to write huge pid file: %v", err)
	}

	_, _, _, err := ReadPID(pidFile)
	if err == nil {
		t.Fatalf("ADV-STAT-02 FAILED: Expected error parsing huge non-numeric PID")
	}
}

// ADV-STAT-03: Probe Hang Defense / Timeout Bounds
// Attack Vector: Server accepts TCP connection but hangs indefinitely without sending bytes.
// Defense: Probe enforces strict timeout context and tears down connection.
func TestADV_SlowServerProbeHang(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	// Server accepts and sleeps
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(2 * time.Second) // Intentionally slow
			}(conn)
		}
	}()

	addr := l.Addr().String()
	start := time.Now()
	timeout := 150 * time.Millisecond

	info, err := Probe(context.Background(), Options{
		Addr:    addr,
		PIDFile: "/nonexistent.pid",
		Timeout: timeout,
	})
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("ADV-STAT-03 FAILED: Probe returned error: %v", err)
	}
	if info.Healthy {
		t.Fatalf("ADV-STAT-03 FAILED: Slow/hanging server must not be marked healthy")
	}

	// Probe should respect timeout (+ reasonable margin for CI)
	if duration > 1*time.Second {
		t.Errorf("ADV-STAT-03 FAILED: Probe took %v, exceeded timeout %v significantly", duration, timeout)
	}
}

// ADV-STAT-04: Giant Health Response Body Flood
// Attack Vector: Adversary sends back a 50MB HTTP response on /healthz to exhaust client RAM.
// Defense: Probe bounds HTTP response read via io.LimitReader to 64KB.
func TestADV_MaliciousLargeHTTPPayload(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("X", 65536)
		for i := 0; i < 50; i++ { // ~3.2MB
			_, _ = w.Write([]byte(chunk))
		}
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

	info, err := Probe(context.Background(), Options{
		Addr:    addr,
		PIDFile: "/nonexistent.pid",
		Timeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}

	// Should safely process without memory leak or crash
	if !info.Healthy {
		t.Errorf("ADV-STAT-04 FAILED: Expected server to be considered healthy (HTTP 200)")
	}
}

// ADV-STAT-05: Malformed and Overflow PID Values
// Attack Vector: Negative PIDs, PID 0, or 64-bit integer overflows.
// Defense: ReadPID validates bounds and ignores non-positive integers.
func TestADV_MalformedPIDValues(t *testing.T) {
	tmpDir := t.TempDir()

	testCases := []struct {
		name    string
		content string
	}{
		{"NegativePID", "-42\n"},
		{"ZeroPID", "0\n"},
		{"OverflowPID", "99999999999999999999999999999999999999999999999999\n"},
		{"WhitespaceOnly", "   \n\t  "},
		{"ControlChars", "\x00\x01\x02"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(tmpDir, tc.name+".pid")
			if err := os.WriteFile(p, []byte(tc.content), 0600); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}
			pid, alive, _, err := ReadPID(p)
			if err == nil && pid > 0 {
				t.Errorf("expected error or pid <= 0 for %s, got pid=%d", tc.name, pid)
			}
			if alive {
				t.Errorf("expected alive=false for %s", tc.name)
			}
		})
	}
}

// ADV-STAT-06: Multi-Agent Concurrency Stress (N=8)
// Requirement: Concurrent subagents querying status simultaneously must not race or deadlock.
func TestADV_ConcurrentStatusProbes(t *testing.T) {
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

	var wg sync.WaitGroup
	errCh := make(chan error, 16)

	const concurrency = 8
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(agentID int) {
			defer wg.Done()
			for iter := 0; iter < 10; iter++ {
				info, err := Probe(context.Background(), Options{
					Addr:    addr,
					PIDFile: "/nonexistent.pid",
					Timeout: 500 * time.Millisecond,
				})
				if err != nil {
					errCh <- fmt.Errorf("agent %d iter %d probe failed: %w", agentID, iter, err)
					return
				}
				if !info.Healthy || info.Status != "online" {
					errCh <- fmt.Errorf("agent %d iter %d unexpected status: %+v", agentID, iter, info)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("ADV-STAT-06 FAILED: %v", err)
	}
}
