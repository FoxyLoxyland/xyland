// Package llm adalah klien LLM OpenAI-compatible xyland (9Router, OpenAI,
// OpenRouter, Ollama, dsb). Antarmukanya sengaja meniru bentuk ChatModel
// pada framework agent Go (Eino) agar adapter Eino bisa dipasang kemudian
// tanpa mengubah pemanggil: Generate(ctx, messages) -> teks.
//
// Bila tidak ada konfigurasi LLM, pemanggil WAJIB memakai jalur heuristik
// deterministik — pipeline tidak boleh gagal hanya karena LLM absen.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Config struct {
	BaseURL string
	APIKey  string
	Model   string
}

func ConfigFromEnv() Config {
	c := Config{
		BaseURL: os.Getenv("XYLAND_LLM_BASE_URL"),
		APIKey:  os.Getenv("XYLAND_LLM_API_KEY"),
		Model:   os.Getenv("XYLAND_LLM_MODEL"),
	}
	if c.Model == "" {
		c.Model = "gpt-4o-mini"
	}
	return c
}

func (c Config) Available() bool { return c.BaseURL != "" }

type Client struct {
	cfg Config
	hc  *http.Client
}

func New(cfg Config) *Client {
	return &Client{cfg: cfg, hc: &http.Client{Timeout: 120 * time.Second}}
}

type chatReq struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type chatResp struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Result membawa teks + pemakaian token (metering oleh engine, docs/11 §6).
type Result struct {
	Text             string
	PromptTokens     int
	CompletionTokens int
}

func (cl *Client) Generate(ctx context.Context, msgs []Message) (*Result, error) {
	body, _ := json.Marshal(chatReq{Model: cl.cfg.Model, Messages: msgs})
	url := strings.TrimRight(cl.cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cl.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cl.cfg.APIKey)
	}
	resp, err := cl.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("llm: status %d", resp.StatusCode)
	}
	var cr chatResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, err
	}
	if len(cr.Choices) == 0 {
		return nil, fmt.Errorf("llm: respons kosong")
	}
	return &Result{
		Text:             cr.Choices[0].Message.Content,
		PromptTokens:     cr.Usage.PromptTokens,
		CompletionTokens: cr.Usage.CompletionTokens,
	}, nil
}
