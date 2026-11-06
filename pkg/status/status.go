package status

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/shield/pkg/proxy"
	"github.com/bonjoski/shield/pkg/version"
)

var (
	// ErrSymlinkDetected is returned when the configured PID file is a symlink.
	ErrSymlinkDetected = errors.New("security violation: PID file is a symlink")
)

// Options configures probe behavior for `shield status`.
type Options struct {
	Addr       string        // Explicit TCP address to check (e.g. "127.0.0.1:8443")
	SocketPath string        // Explicit Unix socket path to check
	PIDFile    string        // Path to PID file (defaults to ~/.shield/shield.pid)
	Timeout    time.Duration // Network probe timeout (defaults to 1s)
}

// Info holds the collected health, network, and process status of Shield proxy.
type Info struct {
	Running        bool              `json:"running"`
	Healthy        bool              `json:"healthy"`
	Status         string            `json:"status"` // "online", "degraded", "offline"
	ListeningAddr  string            `json:"listening_addr,omitempty"`
	Protocol       string            `json:"protocol,omitempty"` // "https", "http", "unix"
	PID            int               `json:"pid,omitempty"`
	PIDRunning     bool              `json:"pid_running"`
	PIDStale       bool              `json:"pid_stale,omitempty"`
	PIDFile        string            `json:"pid_file,omitempty"`
	Uptime         string            `json:"uptime,omitempty"`
	Version        string            `json:"version"`
	ProbeEndpoint  string            `json:"probe_endpoint,omitempty"`
	ProbeResponse  map[string]string `json:"probe_response,omitempty"`
	CheckedTargets []string          `json:"checked_targets,omitempty"`
	Error          string            `json:"error,omitempty"`
}

// Probe inspects the proxy process and probes network listeners for health.
func Probe(ctx context.Context, opts Options) (*Info, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 1 * time.Second
	}

	pidFile := opts.PIDFile
	if pidFile == "" {
		pidFile = proxy.DefaultPIDPath()
	}

	info := &Info{
		Version: version.Version,
		PIDFile: proxy.ExpandPath(pidFile),
		Status:  "offline",
	}

	// 1. Check PID file and process liveness
	pid, isAlive, isStale, pidErr := ReadPID(info.PIDFile)
	if pid > 0 {
		info.PID = pid
		info.PIDRunning = isAlive
		info.PIDStale = isStale
		if isAlive {
			info.Uptime = GetProcessUptime(ctx, pid)
		}
	} else if pidErr != nil && !errors.Is(pidErr, os.ErrNotExist) {
		info.Error = fmt.Sprintf("PID check warning: %v", pidErr)
	}

	// 2. Determine target candidates to probe
	type candidate struct {
		isSocket bool
		addr     string
	}
	var candidates []candidate

	if opts.SocketPath != "" {
		candidates = append(candidates, candidate{isSocket: true, addr: proxy.ExpandPath(opts.SocketPath)})
	} else if opts.Addr != "" {
		candidates = append(candidates, candidate{isSocket: false, addr: opts.Addr})
	} else {
		// Auto-discovery mode:
		// Check default socket if it exists on filesystem
		defaultSock := proxy.DefaultSocketPath()
		if fi, err := os.Lstat(defaultSock); err == nil && fi.Mode()&os.ModeSymlink == 0 {
			candidates = append(candidates, candidate{isSocket: true, addr: defaultSock})
		}

		// Environment override
		if envAddr := os.Getenv("SHIELD_PROXY_ADDR"); envAddr != "" {
			candidates = append(candidates, candidate{isSocket: false, addr: envAddr})
		}

		// Standard ecosystem defaults
		candidates = append(candidates,
			candidate{isSocket: false, addr: "127.0.0.1:8443"},
			candidate{isSocket: false, addr: "127.0.0.1:8080"},
		)
	}

	// Deduplicate candidates
	seen := make(map[string]bool)
	var uniqueCandidates []candidate
	for _, c := range candidates {
		key := fmt.Sprintf("%v:%s", c.isSocket, c.addr)
		if !seen[key] {
			seen[key] = true
			uniqueCandidates = append(uniqueCandidates, c)
		}
	}

	// 3. Probe candidate endpoints
	for _, c := range uniqueCandidates {
		targetLabel := c.addr
		if c.isSocket {
			targetLabel = "unix://" + c.addr
		}
		info.CheckedTargets = append(info.CheckedTargets, targetLabel)

		if c.isSocket {
			healthy, respData, err := probeUnixSocket(ctx, c.addr, opts.Timeout)
			if healthy {
				info.Running = true
				info.Healthy = true
				info.Status = "online"
				info.Protocol = "unix"
				info.ListeningAddr = "unix://" + c.addr
				info.ProbeEndpoint = "http://localhost/healthz"
				info.ProbeResponse = respData
				break
			}
			_ = err
		} else {
			// Probe TCP: Try HTTPS first, then fallback to HTTP
			healthy, proto, respData, err := probeTCP(ctx, c.addr, opts.Timeout)
			if healthy {
				info.Running = true
				info.Healthy = true
				info.Status = "online"
				info.Protocol = proto
				info.ListeningAddr = fmt.Sprintf("%s://%s", proto, c.addr)
				info.ProbeEndpoint = fmt.Sprintf("%s://%s/healthz", proto, c.addr)
				info.ProbeResponse = respData
				break
			}
			_ = err
		}
	}

	// 4. Synthesize final state
	if info.Healthy {
		if pidErr != nil && !errors.Is(pidErr, os.ErrNotExist) {
			info.Error = fmt.Sprintf("PID check warning: %v", pidErr)
		} else {
			info.Error = ""
		}
	} else if info.PIDRunning {
		info.Running = true
		info.Status = "degraded"
		errMsg := fmt.Sprintf("Shield proxy process is running (PID %d) but health probe failed on %s", info.PID, strings.Join(info.CheckedTargets, ", "))
		if pidErr != nil && !errors.Is(pidErr, os.ErrNotExist) {
			errMsg = fmt.Sprintf("%s; PID check warning: %v", errMsg, pidErr)
		}
		info.Error = errMsg
	} else {
		info.Running = false
		info.Status = "offline"
		var errMsg string
		if len(info.CheckedTargets) == 1 {
			errMsg = fmt.Sprintf("Shield proxy is not running (%s offline)", info.CheckedTargets[0])
		} else if len(info.CheckedTargets) > 0 {
			errMsg = fmt.Sprintf("Shield proxy is not running (checked: %s offline)", strings.Join(info.CheckedTargets, ", "))
		} else {
			errMsg = "Shield proxy is not running (ports offline)"
		}
		if pidErr != nil && !errors.Is(pidErr, os.ErrNotExist) {
			errMsg = fmt.Sprintf("%s; PID check warning: %v", errMsg, pidErr)
		}
		info.Error = errMsg
	}

	return info, nil
}

// ReadPID reads a PID file safely, verifying it is not a symlink.
func ReadPID(pidPath string) (pid int, isRunning bool, isStale bool, err error) {
	fi, err := os.Lstat(pidPath)
	if err != nil {
		return 0, false, false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return 0, false, false, ErrSymlinkDetected
	}

	f, err := os.Open(pidPath)
	if err != nil {
		return 0, false, false, err
	}
	defer f.Close()

	// Limit reader to 64 bytes to prevent memory exhaustion
	data, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return 0, false, false, err
	}

	val, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || val <= 0 {
		return 0, false, false, fmt.Errorf("invalid PID value in file: %q", string(data))
	}

	alive := IsProcessAlive(val)
	return val, alive, !alive, nil
}

// IsProcessAlive checks whether a process with the given PID is currently running.
func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Sending signal 0 checks process existence.
	err = process.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	if errors.Is(err, syscall.EPERM) {
		return true
	}
	return false
}

// GetProcessUptime retrieves elapsed time string (e.g. "02-19:24:25" or "05:12") using `ps`.
func GetProcessUptime(ctx context.Context, pid int) string {
	if pid <= 0 {
		return ""
	}
	psCtx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(psCtx, "ps", "-p", strconv.Itoa(pid), "-o", "etime=")
	out, err := cmd.Output()
	if err == nil {
		uptime := strings.TrimSpace(string(out))
		if uptime != "" {
			return uptime
		}
	}
	return ""
}

func probeUnixSocket(ctx context.Context, sockPath string, timeout time.Duration) (bool, map[string]string, error) {
	tr := &http.Transport{
		DialContext: func(dCtx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(dCtx, "unix", sockPath)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/healthz", nil)
	if err != nil {
		return false, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	var data map[string]string
	_ = json.Unmarshal(body, &data)

	return true, data, nil
}

func probeTCP(ctx context.Context, addr string, timeout time.Duration) (bool, string, map[string]string, error) {
	// 1. Try HTTPS
	tlsTr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Local loopback self-signed / internal CA probe
		},
		DisableKeepAlives: true,
	}
	httpsClient := &http.Client{
		Transport: tlsTr,
		Timeout:   timeout,
	}

	httpsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/healthz", addr), nil)
	if err == nil {
		resp, err := httpsClient.Do(httpsReq)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
				var data map[string]string
				_ = json.Unmarshal(body, &data)
				return true, "https", data, nil
			}
		}
	}

	// 2. Try plain HTTP
	httpTr := &http.Transport{
		DisableKeepAlives: true,
	}
	httpClient := &http.Client{
		Transport: httpTr,
		Timeout:   timeout,
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s/healthz", addr), nil)
	if err == nil {
		resp, err := httpClient.Do(httpReq)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
				var data map[string]string
				_ = json.Unmarshal(body, &data)
				return true, "http", data, nil
			}
		}
	}

	return false, "", nil, errors.New("connection failed or endpoint unhealthy")
}

// FormatHuman formats the status info into clean human-readable output.
func (s *Info) FormatHuman() string {
	var b strings.Builder
	statusUpper := strings.ToUpper(s.Status)
	icon := "🛡️ "

	b.WriteString(fmt.Sprintf("%s Shield Proxy Status: %s\n", icon, statusUpper))
	b.WriteString(strings.Repeat("─", 65) + "\n")

	switch s.Status {
	case "online":
		b.WriteString(fmt.Sprintf("  Status:          Active (healthy)\n"))
		b.WriteString(fmt.Sprintf("  Listening:       %s\n", s.ListeningAddr))
		protoDesc := strings.ToUpper(s.Protocol)
		if s.Protocol == "https" {
			protoDesc = "HTTPS (TLS wire guard active)"
		} else if s.Protocol == "unix" {
			protoDesc = "Unix Domain Socket (zero network surface)"
		} else if s.Protocol == "http" {
			protoDesc = "HTTP (loopback plaintext)"
		}
		b.WriteString(fmt.Sprintf("  Protocol:        %s\n", protoDesc))

		if len(s.ProbeResponse) > 0 {
			var details []string
			for k, v := range s.ProbeResponse {
				details = append(details, fmt.Sprintf("%s=%s", k, v))
			}
			b.WriteString(fmt.Sprintf("  Health Probe:    OK (/healthz: %s)\n", strings.Join(details, ", ")))
		} else {
			b.WriteString("  Health Probe:    OK (200 OK)\n")
		}

	case "degraded":
		b.WriteString(fmt.Sprintf("  Status:          Degraded (process running, probe failed)\n"))
		if len(s.CheckedTargets) > 0 {
			b.WriteString(fmt.Sprintf("  Checked Targets: %s (offline)\n", strings.Join(s.CheckedTargets, ", ")))
		}

	default: // offline
		b.WriteString(fmt.Sprintf("  Status:          Stopped (proxy offline)\n"))
		if len(s.CheckedTargets) > 0 {
			b.WriteString(fmt.Sprintf("  Checked Targets: %s (offline)\n", strings.Join(s.CheckedTargets, ", ")))
		}
	}

	if s.PIDRunning {
		uptimeStr := ""
		if s.Uptime != "" {
			uptimeStr = fmt.Sprintf(", uptime: %s", s.Uptime)
		}
		b.WriteString(fmt.Sprintf("  PID:             %d (running%s)\n", s.PID, uptimeStr))
	} else if s.PIDStale {
		b.WriteString(fmt.Sprintf("  PID:             %d (stale / not running)\n", s.PID))
	} else {
		b.WriteString("  PID:             None\n")
	}

	b.WriteString(fmt.Sprintf("  Version:         %s\n", s.Version))
	b.WriteString(strings.Repeat("─", 65) + "\n")

	if s.Status != "online" {
		if s.Error != "" {
			b.WriteString(fmt.Sprintf("  %s\n", s.Error))
		}
		b.WriteString("  To start: shield proxy --addr 127.0.0.1:8443 --tls\n")
	}

	return b.String()
}

// FormatJSON renders status info into formatted JSON.
func (s *Info) FormatJSON() (string, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
