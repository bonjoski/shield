package provider

import (
	"context"
	"strings"
	"testing"
)

func TestMockProvider(t *testing.T) {
	mock := NewMockProvider("test-mock", "Default response")
	mock.SetReply("explain_error", "The error occurred because permission was denied on /etc/passwd")

	ctx := context.Background()

	// Test default
	resp, err := mock.Complete(ctx, Request{
		Messages: []Message{{Role: RoleUser, Content: "Hello world"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "Default response" {
		t.Errorf("expected default response, got: %s", resp.Content)
	}

	// Test matching reply
	resp2, err := mock.Complete(ctx, Request{
		Messages: []Message{{Role: RoleUser, Content: "Please explain_error in sandbox"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(resp2.Content, "permission was denied") {
		t.Errorf("expected custom reply, got: %s", resp2.Content)
	}

	if mock.CallCount() != 2 {
		t.Errorf("expected 2 calls, got %d", mock.CallCount())
	}
}

func TestEmptyPromptValidation(t *testing.T) {
	mock := NewMockProvider("", "")
	_, err := mock.Complete(context.Background(), Request{})
	if err != ErrEmptyPrompt {
		t.Errorf("expected ErrEmptyPrompt, got: %v", err)
	}
}
