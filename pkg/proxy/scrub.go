package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/shield"
)

var errInvalidPayload = errors.New("invalid JSON request object")

func isSafeStructuralEnum(key, val string) bool {
	switch key {
	case "role":
		switch val {
		case "user", "assistant", "system", "developer", "tool", "function", "model":
			return true
		}
	case "type":
		switch val {
		case "text", "image", "image_url", "tool_use", "tool_result", "function", "input_text", "output_text", "thinking":
			return true
		}
	case "model":
		return provider.ValidateModelName(val) == nil
	}
	return false
}

// scrubJSONValue recursively walks an arbitrary JSON payload (supporting OpenAI, Anthropic,
// Gemini, multimodal content arrays, system blocks, and tool_calls) and redacts all string
// leaves into the shared request-scoped TokenMap.
func scrubJSONValue(v any, parentKey string, engine *shield.Engine, tm *shield.TokenMap) (any, error) {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, child := range typed {
			scrubbedKey, err := engine.RedactWithTokenMap(k, tm)
			if err != nil {
				return nil, err
			}
			scrubbedChild, err := scrubJSONValue(child, k, engine, tm)
			if err != nil {
				return nil, err
			}
			out[scrubbedKey] = scrubbedChild
		}
		return out, nil

	case []any:
		out := make([]any, len(typed))
		for i, elem := range typed {
			scrubbedElem, err := scrubJSONValue(elem, parentKey, engine, tm)
			if err != nil {
				return nil, err
			}
			out[i] = scrubbedElem
		}
		return out, nil

	case string:
		if isSafeStructuralEnum(parentKey, typed) {
			return typed, nil
		}
		return engine.RedactWithTokenMap(typed, tm)

	default:
		return v, nil
	}
}

// buildProviderRequestFromScrubbed extracts a normalized provider.Request from a scrubbed
// OpenAI, Anthropic, or Gemini JSON object.
func buildProviderRequestFromScrubbed(doc map[string]any) (provider.Request, error) {
	if doc == nil {
		return provider.Request{}, errInvalidPayload
	}

	var req provider.Request
	if m, ok := doc["model"].(string); ok {
		req.Model = strings.TrimSpace(m)
		if req.Model != "" {
			if err := provider.ValidateModelName(req.Model); err != nil {
				return provider.Request{}, err
			}
		}
	}

	// Extract top-level system prompt (Anthropic `system` string/blocks, `system_prompt`, or Gemini `systemInstruction`)
	var sysParts []string
	if sysVal, exists := doc["system"]; exists {
		if text := flattenContentValue(sysVal); text != "" {
			sysParts = append(sysParts, text)
		}
	}
	if sysPrompt, ok := doc["system_prompt"].(string); ok && sysPrompt != "" {
		sysParts = append(sysParts, sysPrompt)
	}
	if sysInst, ok := doc["systemInstruction"].(map[string]any); ok {
		if text := flattenContentValue(sysInst["parts"]); text != "" {
			sysParts = append(sysParts, text)
		}
	}
	if len(sysParts) > 0 {
		req.SystemPrompt = strings.Join(sysParts, "\n")
	}

	// Extract messages (`messages` for OpenAI/Anthropic, or `contents` for Gemini)
	if rawMsgs, ok := doc["messages"].([]any); ok {
		for _, item := range rawMsgs {
			msgMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			role, _ := msgMap["role"].(string)
			if role == "" {
				role = provider.RoleUser
			}

			var parts []string
			if cVal, exists := msgMap["content"]; exists {
				if text := flattenContentValue(cVal); text != "" {
					parts = append(parts, text)
				}
			}
			if tcVal, exists := msgMap["tool_calls"]; exists {
				if text := flattenToolCalls(tcVal); text != "" {
					parts = append(parts, text)
				}
			}

			req.Messages = append(req.Messages, provider.Message{
				Role:    role,
				Content: strings.Join(parts, "\n"),
			})
		}
	} else if rawContents, ok := doc["contents"].([]any); ok {
		for _, item := range rawContents {
			cMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			role, _ := cMap["role"].(string)
			if role == "" || role == "user" {
				role = provider.RoleUser
			} else if role == "model" {
				role = provider.RoleAssistant
			}
			text := flattenContentValue(cMap["parts"])
			req.Messages = append(req.Messages, provider.Message{
				Role:    role,
				Content: text,
			})
		}
	}

	return req, nil
}

func flattenContentValue(v any) string {
	switch typed := v.(type) {
	case string:
		return typed
	case []any:
		var segments []string
		for _, elem := range typed {
			if s := flattenContentValue(elem); s != "" {
				segments = append(segments, s)
			}
		}
		return strings.Join(segments, "\n")
	case map[string]any:
		var segments []string
		for _, field := range []string{"text", "content", "input", "arguments"} {
			if val, exists := typed[field]; exists {
				if s := flattenContentValue(val); s != "" {
					segments = append(segments, s)
				}
			}
		}
		if len(segments) > 0 {
			return strings.Join(segments, "\n")
		}
		b, err := json.Marshal(typed)
		if err == nil {
			return string(b)
		}
	}
	return ""
}

func flattenToolCalls(v any) string {
	arr, ok := v.([]any)
	if !ok {
		return ""
	}
	var calls []string
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if fn, ok := m["function"].(map[string]any); ok {
			name, _ := fn["name"].(string)
			args, _ := fn["arguments"].(string)
			calls = append(calls, fmt.Sprintf("%s(%s)", name, args))
			continue
		}
		if b, err := json.Marshal(m); err == nil {
			calls = append(calls, string(b))
		}
	}
	return strings.Join(calls, "\n")
}
