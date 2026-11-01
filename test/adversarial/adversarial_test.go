package adversarial

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/proxy"
	"github.com/bonjoski/shield/pkg/reassembly"
	"github.com/bonjoski/shield/pkg/shield"
)

// ADV-01: Zero-Width Space & Unicode Smuggling Bypass
// Adversary injects zero-width invisible characters (\u200b, \u200c, \u200d, \ufeff)
// to break naive regex patterns and entropy scanning.
func TestADV01_ZeroWidthUnicodeSmuggling(t *testing.T) {
	cfg := shield.DefaultConfig()
	engine := shield.NewEngine(cfg)

	// Injected AWS Key with zero-width space
	smuggledAWS := "AKIA\u200bIOSFODNN7EXAMPLE"
	// Injected Anthropic Key with zero-width non-joiner
	smuggledAnthropic := "sk-ant-\u200capi03-abcdefghijklmnopqrstuvwxyz1234567890_test"

	payload := "Config: " + smuggledAWS + " and " + smuggledAnthropic

	redacted, tm, err := engine.Redact(payload)
	if err != nil {
		t.Fatalf("redact failed: %v", err)
	}

	// Verify secrets were caught despite unicode smuggling
	if strings.Contains(redacted, "AKIA") {
		t.Errorf("ADV-01 FAILED: Smuggled AWS key bypassed redaction: %s", redacted)
	}
	if strings.Contains(redacted, "sk-ant-") {
		t.Errorf("ADV-01 FAILED: Smuggled Anthropic key bypassed redaction: %s", redacted)
	}

	// Verify WireGuard blocks unredacted smuggled payload
	if err := engine.FailClosedWireGuard([]byte(payload)); err == nil {
		t.Errorf("ADV-01 FAILED: FailClosedWireGuard allowed smuggled unredacted payload")
	}

	// Restored should yield clean token without leaks
	restored := engine.Restore(redacted, tm)
	if !strings.Contains(restored, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("ADV-01 FAILED: Restored payload does not contain original clean secret")
	}
}

// ADV-02: High-Entropy Word Exfiltration Detection
// Adversary uses an unformatted, un-prefixed high-entropy secret (e.g. random base64/hex token).
func TestADV02_HighEntropyWordExfiltration(t *testing.T) {
	cfg := shield.DefaultConfig()
	engine := shield.NewEngine(cfg)

	// High entropy un-prefixed token
	highEntropySecret := "k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ"
	payload := "Authorization token: " + highEntropySecret

	redacted, _, err := engine.Redact(payload)
	if err != nil {
		t.Fatalf("redact failed: %v", err)
	}

	if strings.Contains(redacted, highEntropySecret) {
		t.Errorf("ADV-02 FAILED: High-entropy raw token escaped redaction: %s", redacted)
	}
	if !strings.Contains(redacted, "[SECRET_REF_") {
		t.Errorf("ADV-02 FAILED: Expected placeholder in redacted output")
	}
}

// ADV-03: Hallucinated Placeholder Injection Attack
// Adversarial LLM attempts to trick local system by hallucinating unmapped [SECRET_REF_...] tokens.
func TestADV03_HallucinatedPlaceholderInjection(t *testing.T) {
	r := reassembly.NewReassembler()
	tm := shield.NewTokenMap()
	validRef := tm.Add("legit_secret", "PROD_KEY")

	// Upstream LLM response includes a fabricated secret reference
	adversarialResponse := "Use " + validRef + " and also fake [SECRET_REF_99999999deadbeef]"

	err := r.CheckUnmappedPlaceholders(adversarialResponse, tm)
	if err == nil {
		t.Fatalf("ADV-03 FAILED: Reassembler accepted hallucinated unmapped token reference")
	}
	if !errors.Is(err, reassembly.ErrUnmappedToken) {
		t.Errorf("ADV-03 FAILED: Unexpected error type: %v", err)
	}
}

// ADV-04: Fail-Closed Wire Guard Blocks Direct Egress
// Simulates an unredacted payload reaching the network layer.
func TestADV04_FailClosedWireGuardBlocksDirectEgress(t *testing.T) {
	cfg := shield.DefaultConfig()
	cfg.CustomVaultKeys["DB_PASSWORD"] = "ultra_secret_db_pass_1234"
	engine := shield.NewEngine(cfg)

	leakVectors := []string{
		"AWS leak: AKIAIOSFODNN7EXAMPLE",
		"Anthropic leak: sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890_test",
		"Vault key leak: ultra_secret_db_pass_1234",
		"Private key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----",
	}

	for _, vector := range leakVectors {
		err := engine.FailClosedWireGuard([]byte(vector))
		if err == nil {
			t.Errorf("ADV-04 FAILED: FailClosedWireGuard permitted leak vector: %s", vector)
		}
	}
}

// ADV-05: In-Memory Cryptographic Zeroization
// Verifies that TokenMap.Zeroize clears all sensitive buffers from memory.
func TestADV05_InMemoryCryptographicZeroization(t *testing.T) {
	tm := shield.NewTokenMap()
	secret1 := "super_secret_token_1"
	secret2 := "super_secret_token_2"

	ref1 := tm.Add(secret1, "KEY_1")
	ref2 := tm.Add(secret2, "KEY_2")

	if tm.Count() != 2 {
		t.Fatalf("expected count 2, got %d", tm.Count())
	}

	tm.Zeroize()

	if tm.Count() != 0 {
		t.Fatalf("ADV-05 FAILED: TokenMap count is %d after Zeroize", tm.Count())
	}

	if _, ok := tm.GetSecret(ref1); ok {
		t.Errorf("ADV-05 FAILED: Secret 1 still retrievable after Zeroize")
	}
	if _, ok := tm.GetSecret(ref2); ok {
		t.Errorf("ADV-05 FAILED: Secret 2 still retrievable after Zeroize")
	}
}

// ADV-06: Adversarial Syntax Corruption Detection
// Verifies that malformed or syntax-corrupted generated code is rejected before local filesystem write.
func TestADV06_AdversarialSyntaxCorruption(t *testing.T) {
	r := reassembly.NewReassembler()

	corruptCode := `
package main
func main() {
	fmt.Println("Broken payload"
`

	err := r.ValidateSyntax("go", corruptCode)
	if err == nil {
		t.Fatalf("ADV-06 FAILED: Reassembler accepted syntactically corrupted Go code")
	}
	if !errors.Is(err, reassembly.ErrSyntaxValidation) {
		t.Errorf("ADV-06 FAILED: Expected ErrSyntaxValidation, got: %v", err)
	}
}

// ADV-07: Unix Domain Socket Symlink Hijack & Permission Snooping Prevention
// Adversary places a symlink at the socket target path pointing to a sensitive file (e.g. /etc/passwd or a secret file).
// Shield must detect the symlink and abort startup without overwriting, unlinking, or writing to the target file.
// In addition, valid socket files must have strict 0600 permissions.
func TestADV07_UnixSocketSymlinkAndPermissionsAttack(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "shld-adv7-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	sensitiveTarget := filepath.Join(tmpDir, "sensitive-vault.txt")
	originalSecret := "SUPER_CRITICAL_USER_DATA_DO_NOT_CLOBBER"
	if err := os.WriteFile(sensitiveTarget, []byte(originalSecret), 0600); err != nil {
		t.Fatal(err)
	}

	symlinkPath := filepath.Join(tmpDir, "shield.sock")
	if err := os.Symlink(sensitiveTarget, symlinkPath); err != nil {
		t.Fatal(err)
	}

	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "OK")

	// 1. Attempt to start server on the symlinked socket path
	srv := proxy.NewServerWithOptions(proxy.Options{
		SocketPath: symlinkPath,
	}, engine, mock)

	err = srv.Start()
	if err == nil {
		_ = srv.Stop(context.Background())
		t.Fatalf("ADV-07 FAILED: Shield started on symlink without detecting hijack attempt")
	}

	if !errors.Is(err, proxy.ErrSymlinkDetected) {
		t.Errorf("ADV-07 FAILED: Expected ErrSymlinkDetected, got: %v", err)
	}

	// Verify target file was NOT clobbered or deleted
	content, err := os.ReadFile(sensitiveTarget)
	if err != nil {
		t.Fatalf("ADV-07 FAILED: Target file was deleted or made unreadable: %v", err)
	}
	if string(content) != originalSecret {
		t.Errorf("ADV-07 FAILED: Target file content was modified: got %s, want %s", string(content), originalSecret)
	}

	// 2. Test legitimate socket path and verify 0600 permissions
	legitSockPath := filepath.Join(tmpDir, "legit.sock")
	legitSrv := proxy.NewServerWithOptions(proxy.Options{
		SocketPath: legitSockPath,
	}, engine, mock)

	if err := legitSrv.Start(); err != nil {
		t.Fatalf("ADV-07 FAILED: Failed to start legitimate socket: %v", err)
	}
	defer legitSrv.Stop(context.Background())

	fi, err := os.Stat(legitSockPath)
	if err != nil {
		t.Fatalf("ADV-07 FAILED: Could not stat legitimate socket: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("ADV-07 FAILED: Insecure socket permissions: expected 0600, got %o", perm)
	}
}

// ADV-08: Rogue & Untrusted TLS Certificate Rejection
// Adversary stands up a MITM or provides a rogue certificate not signed by the trusted Locksmith Root CA.
// Client configured to trust the legitimate Locksmith Root CA must reject the TLS handshake.
func TestADV08_RogueAndUntrustedTLSCertRejection(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Legitimate Locksmith Root CA
	legitCAPEM, legitCAKeyPEM := generateTestCA(t, "Locksmith Root CA")

	// 2. Rogue CA and server cert signed by rogue CA
	rogueCAPEM, rogueCAKeyPEM := generateTestCA(t, "Rogue Untrusted CA")
	rogueCertPEM, rogueKeyPEM := generateTestCert(t, rogueCAPEM, rogueCAKeyPEM, true, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	rogueCertFile := filepath.Join(tempDir, "rogue.crt")
	rogueKeyFile := filepath.Join(tempDir, "rogue.key")
	_ = os.WriteFile(rogueCertFile, rogueCertPEM, 0600)
	_ = os.WriteFile(rogueKeyFile, rogueKeyPEM, 0600)

	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "OK")

	// Server running with rogue cert
	srv := proxy.NewServerWithOptions(proxy.Options{
		Addr:     "127.0.0.1:0",
		TLS:      true,
		CertFile: rogueCertFile,
		KeyFile:  rogueKeyFile,
	}, engine, mock)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop(context.Background())

	addr := srv.ListenerAddr().String()

	// Client trusting ONLY legitimate Locksmith Root CA
	legitPool := x509.NewCertPool()
	legitPool.AppendCertsFromPEM(legitCAPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: legitPool,
			},
		},
	}

	// Handshake must fail because server cert was signed by Rogue CA
	_, err := client.Get("https://" + addr + "/healthz")
	if err == nil {
		t.Fatalf("ADV-08 FAILED: Client accepted rogue untrusted server certificate")
	}

	// 3. Now verify legitimate cert signed by legit CA succeeds
	legitCertPEM, legitKeyPEM := generateTestCert(t, legitCAPEM, legitCAKeyPEM, true, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	legitCertFile := filepath.Join(tempDir, "legit.crt")
	legitKeyFile := filepath.Join(tempDir, "legit.key")
	_ = os.WriteFile(legitCertFile, legitCertPEM, 0600)
	_ = os.WriteFile(legitKeyFile, legitKeyPEM, 0600)

	legitSrv := proxy.NewServerWithOptions(proxy.Options{
		Addr:     "127.0.0.1:0",
		TLS:      true,
		CertFile: legitCertFile,
		KeyFile:  legitKeyFile,
	}, engine, mock)

	if err := legitSrv.Start(); err != nil {
		t.Fatalf("failed to start legit server: %v", err)
	}
	defer legitSrv.Stop(context.Background())

	legitAddr := legitSrv.ListenerAddr().String()
	resp, err := client.Get("https://" + legitAddr + "/healthz")
	if err != nil {
		t.Fatalf("ADV-08 FAILED: Client rejected legitimate Locksmith-anchored cert: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
}

// ADV-09: mTLS Client Certificate Bypass & Impersonation
// When --client-ca is configured on Shield, an adversary without a valid client certificate or with
// a certificate signed by an untrusted CA must be rejected during the TLS handshake before any payload is sent.
func TestADV09_MTLSClientCertificateBypass(t *testing.T) {
	tempDir := t.TempDir()

	serverCAPEM, serverCAKeyPEM := generateTestCA(t, "Shield Server CA")
	serverCertPEM, serverKeyPEM := generateTestCert(t, serverCAPEM, serverCAKeyPEM, true, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	clientCAPEM, clientCAKeyPEM := generateTestCA(t, "Shield Client CA")
	validClientCertPEM, validClientKeyPEM := generateTestCert(t, clientCAPEM, clientCAKeyPEM, false, nil, nil)

	rogueCAPEM, rogueCAKeyPEM := generateTestCA(t, "Rogue Client CA")
	rogueClientCertPEM, rogueClientKeyPEM := generateTestCert(t, rogueCAPEM, rogueCAKeyPEM, false, nil, nil)

	serverCertFile := filepath.Join(tempDir, "server.crt")
	serverKeyFile := filepath.Join(tempDir, "server.key")
	clientCAFile := filepath.Join(tempDir, "client-ca.crt")

	_ = os.WriteFile(serverCertFile, serverCertPEM, 0600)
	_ = os.WriteFile(serverKeyFile, serverKeyPEM, 0600)
	_ = os.WriteFile(clientCAFile, clientCAPEM, 0644)

	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "OK")

	srv := proxy.NewServerWithOptions(proxy.Options{
		Addr:     "127.0.0.1:0",
		TLS:      true,
		CertFile: serverCertFile,
		KeyFile:  serverKeyFile,
		ClientCA: clientCAFile,
	}, engine, mock)

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start mTLS server: %v", err)
	}
	defer srv.Stop(context.Background())

	addr := srv.ListenerAddr().String()
	serverPool := x509.NewCertPool()
	serverPool.AppendCertsFromPEM(serverCAPEM)

	// Vector 1: No client certificate
	clientNoCert := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: serverPool,
			},
		},
	}
	_, err := clientNoCert.Get("https://" + addr + "/healthz")
	if err == nil {
		t.Fatalf("ADV-09 FAILED: Server allowed connection without mTLS client cert")
	}

	// Vector 2: Rogue client certificate signed by untrusted CA
	rogueTLSCert, _ := tls.X509KeyPair(rogueClientCertPEM, rogueClientKeyPEM)
	clientRogueCert := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      serverPool,
				Certificates: []tls.Certificate{rogueTLSCert},
			},
		},
	}
	_, err = clientRogueCert.Get("https://" + addr + "/healthz")
	if err == nil {
		t.Fatalf("ADV-09 FAILED: Server accepted rogue client certificate signed by untrusted CA")
	}

	// Vector 3: Valid client certificate signed by configured Client CA
	validTLSCert, _ := tls.X509KeyPair(validClientCertPEM, validClientKeyPEM)
	clientValidCert := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      serverPool,
				Certificates: []tls.Certificate{validTLSCert},
			},
		},
	}
	resp, err := clientValidCert.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("ADV-09 FAILED: Server rejected valid mTLS client cert: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
}

// ADV-10: Plaintext Downgrade & Cleartext Injection Mitigation
// Adversary attempts to send raw plaintext HTTP requests to an active HTTPS listener.
// Shield TLS listener must reject the cleartext stream at the TLS handshake layer without returning HTTP 200.
func TestADV10_PlaintextDowngradeMitigation(t *testing.T) {
	tempDir := t.TempDir()
	caCertPEM, caKeyPEM := generateTestCA(t, "Locksmith Root CA")
	serverCertPEM, serverKeyPEM := generateTestCert(t, caCertPEM, caKeyPEM, true, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	_ = os.WriteFile(certFile, serverCertPEM, 0600)
	_ = os.WriteFile(keyFile, serverKeyPEM, 0600)

	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "OK")

	srv := proxy.NewServerWithOptions(proxy.Options{
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

	// Connect with raw TCP connection and send unencrypted HTTP request
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect TCP to server: %v", err)
	}
	defer conn.Close()

	plaintextReq := "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	_, _ = conn.Write([]byte(plaintextReq))

	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, readErr := conn.Read(buf)

	// Since it's a TLS listener, plaintext request either returns TLS alert bytes (e.g. \x15\x03\x03...) or immediate connection reset/error
	if readErr == nil && n > 0 {
		responseStr := string(buf[:n])
		if strings.HasPrefix(responseStr, "HTTP/1.1 200") {
			t.Fatalf("ADV-10 FAILED: HTTPS listener responded with HTTP 200 OK to unencrypted plaintext request!")
		}
	}
}

// ADV-11: Harvest-Now-Decrypt-Later (HNDL) & Quantum Key Exchange Downgrade Resistance
// When an adversarial eavesdropper records TLS sessions to decrypt later with a cryptanalytically
// relevant quantum computer (CRQC), Shield must enforce post-quantum hybrid key encapsulation
// (X25519MLKEM768 / SecP256r1MLKEM768 - NIST FIPS 203) over classical ECDH curves.
// This test verifies that even if an adversary tampers with or offers classical curves (X25519, P-256)
// alongside post-quantum hybrid curves, Shield strictly prioritizes and negotiates X25519MLKEM768.
func TestADV11_PostQuantumKeyExchangeDowngradeResistance(t *testing.T) {
	tempDir := t.TempDir()
	caCertPEM, caKeyPEM := generateTestCA(t, "Locksmith Root CA")
	serverCertPEM, serverKeyPEM := generateTestCert(t, caCertPEM, caKeyPEM, true, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	_ = os.WriteFile(certFile, serverCertPEM, 0600)
	_ = os.WriteFile(keyFile, serverKeyPEM, 0600)

	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "OK")

	srv := proxy.NewServerWithOptions(proxy.Options{
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

	// Client advertising both classical curves and post-quantum hybrid curve
	clientTLSConfig := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,      // classical curve listed first by adversary
			tls.X25519,         // classical curve
			tls.X25519MLKEM768, // post-quantum hybrid curve
		},
	}

	conn, err := tls.Dial("tcp", addr, clientTLSConfig)
	if err != nil {
		t.Fatalf("failed tls.Dial: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	// Shield must enforce post-quantum hybrid key exchange (X25519MLKEM768 = CurveID 4588)
	if state.CurveID != tls.X25519MLKEM768 {
		t.Errorf("ADV-11 FAILED: Server permitted downgrade to classical curve %s (%d) instead of X25519MLKEM768 (%d)",
			state.CurveID, state.CurveID, tls.X25519MLKEM768)
	}
}

// Helpers for ephemeral adversarial test certificates
func generateTestCA(t *testing.T, commonName string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
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
			CommonName: "Shield Adversarial Test Cert",
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
