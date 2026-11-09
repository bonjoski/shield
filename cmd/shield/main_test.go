package main

import (
	"context"
	"testing"

	"github.com/bonjoski/shield/pkg/dbguard"
)

func TestSHD03_BuildDBTokenVerifierFailClosed(t *testing.T) {
	// 1. Missing secret & allowed tokens without --insecure-allow-unverified-db-tokens MUST fail closed
	if _, err := buildDBTokenVerifier(true, "", nil, false); err == nil {
		t.Fatal("expected error when neither token secret nor allowed tokens nor insecure opt-in is configured")
	}

	// 2. Disabling --require-token without --insecure-allow-unverified-db-tokens MUST fail closed
	if _, err := buildDBTokenVerifier(false, "super-secret-hmac-key", nil, false); err == nil {
		t.Fatal("expected error when --require-token=false without --insecure-allow-unverified-db-tokens")
	}

	// 3. Valid HMAC secret rejects arbitrary unverified tokens and accepts properly signed tokens
	v, err := buildDBTokenVerifier(true, "prod-hmac-secret-key-2026", nil, false)
	if err != nil {
		t.Fatalf("unexpected error constructing HMAC verifier: %v", err)
	}
	if err := v.VerifyToken(context.Background(), "forged_arbitrary_token"); err == nil {
		t.Fatal("expected forged unverified token to be rejected")
	}
	validTok := dbguard.SignDBToken("prod-hmac-secret-key-2026", "session:subagent-1")
	if err := v.VerifyToken(context.Background(), validTok); err != nil {
		t.Fatalf("expected signed token to verify cleanly, got: %v", err)
	}

	// 4. Explicit opt-in --insecure-allow-unverified-db-tokens permits dev mode
	devV, err := buildDBTokenVerifier(false, "", nil, true)
	if err != nil || devV == nil {
		t.Fatalf("expected explicit insecure opt-in to construct dev verifier, got err=%v", err)
	}
}
