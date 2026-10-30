package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type OllamaProvider struct {
	baseURL    string
	model      string
	httpClient *http.Client
}

func NewOllamaProvider(baseURL string, model string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "qwen2.5-coder:latest"
	}
	return &OllamaProvider{
		baseURL:    baseURL,
		model:      model,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (o *OllamaProvider) Name() string {
	return "ollama-local"
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type ollamaChatResponse struct {
	Model      string        `json:"model"`
	CreatedAt  string        `json:"created_at"`
	Message    ollamaMessage `json:"message"`
	Done       bool          `json:"done"`
	TotalDuration int64      `json:"total_duration"`
	PromptEvalCount int      `json:"prompt_eval_count"`
	EvalCount       int      `json:"eval_count"`
}

func (o *OllamaProvider) Complete(ctx context.Context, req Request) (*Response, error) {
	model := req.Model
	if model == "" {
		model = o.model
	}

	messages := make([]ollamaMessage, 0, len(req.Messages)+1)
	if req.SystemPrompt != "" {
		messages = append(messages, ollamaMessage{
			Role:    RoleSystem,
			Content: req.SystemPrompt,
		})
	}
	for _, m := range req.Messages {
		messages = append(messages, ollamaMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	olReq := ollamaChatRequest{
		Model:    model,
		Messages: messages,
		Stream:   false,
	}

	bodyBytes, err := json.Marshal(olReq)
	if err != nil {
		return nil, fmt.Errorf("ollama marshal error: %w", err)
	}

	url := fmt.Sprintf("%s/api/chat", o.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("ollama request creation failed: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to connect to local Ollama daemon at %s: %v", ErrProviderFailed, o.baseURL, err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("ollama read response failed: %w", err)
	}

	var olResp ollamaChatResponse
	if err := json.Unmarshal(respBytes, &olResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	return &Response{
		Content:      olResp.Message.Content,
		Model:        model,
		FinishReason: "stop",
		Usage: TokenUsage{
			InputTokens:  olResp.PromptEvalCount,
			OutputTokens: olResp.EvalCount,
		},
	}, nil
}
