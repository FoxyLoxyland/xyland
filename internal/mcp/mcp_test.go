package mcp

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func call(t *testing.T, s *Server, id int, method string, params string) map[string]any {
	t.Helper()
	req := rpcReq{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: method}
	if params != "" {
		req.Params = json.RawMessage(params)
	}
	_ = id
	resp := s.handle(req)
	if resp == nil {
		t.Fatalf("respons nil untuk %s", method)
	}
	if resp.Error != nil {
		t.Fatalf("error untuk %s: %s", method, resp.Error.Message)
	}
	raw, _ := json.Marshal(resp.Result)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func TestMCPFlow(t *testing.T) {
	s := &Server{SkillsDir: filepath.Join("..", "..", "skills"), CVEDir: filepath.Join("..", "..", "knowledge", "cve")}
	init := call(t, s, 1, "initialize", "")
	if init["serverInfo"] == nil {
		t.Fatal("initialize harus memuat serverInfo")
	}
	list := call(t, s, 2, "tools/list", "")
	tools, _ := list["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("harus 4 tools, dapat %d", len(tools))
	}
	sk := call(t, s, 3, "tools/call", `{"name":"xyland_skills","arguments":{}}`)
	content, _ := sk["content"].([]any)
	if len(content) == 0 {
		t.Fatal("skills tanpa konten")
	}
	txt, _ := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(txt, "xss-reflected") {
		t.Fatalf("daftar skill tidak lengkap: %.100s", txt)
	}
	fl := call(t, s, 4, "tools/call", `{"name":"xyland_flow","arguments":{}}`)
	fc, _ := fl["content"].([]any)
	ftxt, _ := fc[0].(map[string]any)["text"].(string)
	if !strings.Contains(ftxt, "HYPOTHESIS") {
		t.Fatal("flow tidak memuat state HYPOTHESIS")
	}
}
