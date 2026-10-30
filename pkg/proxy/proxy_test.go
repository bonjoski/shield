package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/shield"
)

func TestProxyEndToEnd(t *testing.T) {
	engine := shield.NewEngine(shield.DefaultConfig())
	mock := provider.NewMockProvider("mock-ai", "Refactored code without secrets.")
	// When mock sees placeholder, it reflects it
	mock.SetReply("[SECRET_REF_", "Refactored code using [SECRET_REF_")

	srv := NewServer("127.0.0.1:8189", engine, mock)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer srv.Stop(context.Background())

	time.Sleep(50 * time.Millisecond)

	// Send prompt with raw AWS key
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

	resp, err := http.Post("http://127.0.0.1:8189/v1/chat/completions", "application/json", bytes.NewReader(body))
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

	t.Logf("Proxy returned response: %s", parsed.Choices[0].Message.Content)
	if mock.CallCount() != 1 {
		t.Errorf("expected mock provider to be called once, got %d", mock.CallCount())
	}
}
