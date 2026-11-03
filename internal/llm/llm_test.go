package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mockOpenAI(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"halo dari mock"}}],"usage":{"prompt_tokens":11,"completion_tokens":7}}`)
	}))
}

// Kedua implementasi (stdlib & adapter Eino) harus menjawab dari endpoint
// OpenAI-compatible yang sama (mock lokal, tanpa jaringan keluar).
func TestStdlibClient(t *testing.T) {
	srv := mockOpenAI(t)
	defer srv.Close()
	cl := New(Config{BaseURL: srv.URL + "/v1", Model: "mock-1"})
	res, err := cl.Generate(context.Background(), []Message{{Role: "user", Content: "hai"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != "halo dari mock" || res.PromptTokens != 11 {
		t.Fatalf("hasil salah: %+v", res)
	}
}

func TestEinoClient(t *testing.T) {
	srv := mockOpenAI(t)
	defer srv.Close()
	cl, err := NewEinoClient(Config{BaseURL: srv.URL + "/v1", Model: "mock-1"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := cl.Generate(context.Background(), []Message{{Role: "system", Content: "s"}, {Role: "user", Content: "hai"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != "halo dari mock" {
		t.Fatalf("eino hasil salah: %+v", res)
	}
	if res.PromptTokens != 11 || res.CompletionTokens != 7 {
		t.Fatalf("eino usage salah: %+v", res)
	}
}
