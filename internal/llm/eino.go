package llm

import (
	"context"
	"os"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/schema"
)

// ChatModel adalah antarmuka lapisan LLM xyland. Dua implementasi:
// Client (stdlib, default) dan EinoClient (adapter CloudWeGo Eino).
type ChatModel interface {
	Generate(ctx context.Context, msgs []Message) (*Result, error)
}

// NewChatModel memilih implementasi: XYLAND_LLM_FRAMEWORK=eino untuk Eino,
// selain itu klien stdlib ramping.
func NewChatModel(cfg Config) ChatModel {
	if os.Getenv("XYLAND_LLM_FRAMEWORK") == "eino" {
		if ec, err := NewEinoClient(cfg); err == nil {
			return ec
		}
	}
	return New(cfg)
}

// EinoClient mengadaptasi Eino ChatModel (OpenAI-compatible) ke antarmuka xyland.
// Flow tetap milik engine xyland; Eino hanya lapisan pemanggilan model (riset putaran 4).
type EinoClient struct {
	cm *einoopenai.ChatModel
}

func NewEinoClient(cfg Config) (*EinoClient, error) {
	cm, err := einoopenai.NewChatModel(context.Background(), &einoopenai.ChatModelConfig{
		BaseURL: cfg.BaseURL,
		APIKey:  cfg.APIKey,
		Model:   cfg.Model,
	})
	if err != nil {
		return nil, err
	}
	return &EinoClient{cm: cm}, nil
}

func (e *EinoClient) Generate(ctx context.Context, msgs []Message) (*Result, error) {
	var in []*schema.Message
	for _, m := range msgs {
		role := schema.User
		switch m.Role {
		case "system":
			role = schema.System
		case "assistant":
			role = schema.Assistant
		}
		in = append(in, &schema.Message{Role: role, Content: m.Content})
	}
	out, err := e.cm.Generate(ctx, in)
	if err != nil {
		return nil, err
	}
	res := &Result{Text: out.Content}
	if out.ResponseMeta != nil && out.ResponseMeta.Usage != nil {
		res.PromptTokens = out.ResponseMeta.Usage.PromptTokens
		res.CompletionTokens = out.ResponseMeta.Usage.CompletionTokens
	}
	return res, nil
}
