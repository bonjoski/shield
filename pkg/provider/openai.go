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

type OpenAIProvider struct {
	apiKey     string
	model      string
	baseURL    string
	httpClient *http.Client
}

func NewOpenAIProvider(apiKey string, model string, baseURL string) *OpenAIProvider {
	if model == "" {
		model = "gpt-4o"
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return &OpenAIProvider{
		apiKey:     apiKey,
		model:      model,
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (o *OpenAIProvider) Name() string {
	return "openai-compatible"
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatRequest struct {
	Model       string              `json:"model"`
	Messages    []openAIChatMessage `json:"messages"`
	Temperature float64             `json:"temperature,omitempty"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (o *OpenAIProvider) Complete(ctx context.Context, req Request) (*Response, error) {
	model := req.Model
	if model == "" {
		model = o.model
	}

	messages := make([]openAIChatMessage, 0, len(req.Messages)+1)
	if req.SystemPrompt != "" {
		messages = append(messages, openAIChatMessage{
			Role:    RoleSystem,
			Content: req.SystemPrompt,
		})
	}
	for _, m := range req.Messages {
		messages = append(messages, openAIChatMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	oReq := openAIChatRequest{
		Model:       model,
		Messages:    messages,
		Temperature: req.Temperature,
	}

	bodyBytes, err := json.Marshal(oReq)
	if err != nil {
		return nil, fmt.Errorf("openai marshal error: %w", err)
	}

	url := fmt.Sprintf("%s/chat/completions", o.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("openai request creation failed: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", o.apiKey))
	}

	httpResp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderFailed, err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("openai read response failed: %w", err)
	}

	var oResp openAIChatResponse
	if err := json.Unmarshal(respBytes, &oResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if oResp.Error != nil {
		return nil, fmt.Errorf("%w: API error: %s", ErrProviderFailed, oResp.Error.Message)
	}

	if len(oResp.Choices) == 0 {
		return nil, fmt.Errorf("%w: no choices returned", ErrInvalidResponse)
	}

	return &Response{
		Content:      oResp.Choices[0].Message.Content,
		Model:        model,
		FinishReason: oResp.Choices[0].FinishReason,
		Usage: TokenUsage{
			InputTokens:  oResp.Usage.PromptTokens,
			OutputTokens: oResp.Usage.CompletionTokens,
		},
	}, nil
}
