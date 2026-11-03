// Package mcp adalah mode MCP server xyland (spec §4 Later): mengekspos
// kemampuan xyland sebagai tools untuk klien AI (Claude & sejenisnya)
// lewat JSON-RPC 2.0 di stdio (newline-delimited).
//
// Tools: xyland_flow, xyland_skills, xyland_cves, xyland_scan.
// Keamanan: scan hanya jalan bila klien memanggilnya secara eksplisit;
// scope guard & safety rules xyland tetap berlaku di dalam agent.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/FoxyLoxyland/xyland/internal/agent"
	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/knowledge"
	"github.com/FoxyLoxyland/xyland/internal/skills"
)

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Server struct {
	SkillsDir string
	CVEDir    string
	OutDir    string
}

func toolDefs() []map[string]any {
	str := map[string]any{"type": "string"}
	return []map[string]any{
		{"name": "xyland_flow", "description": "Tampilkan state machine flow xyland dan State Brief tiap state.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
		{"name": "xyland_skills", "description": "Daftar skill pada library xyland (nama + deskripsi).", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
		{"name": "xyland_cves", "description": "Daftar kartu CVE terkurasi pada knowledge base xyland.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
		{"name": "xyland_scan", "description": "Jalankan scan xyland ke target (wajib in-scope). dry_run=true berhenti sebelum eksekusi aktif.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"target": str, "dry_run": map[string]any{"type": "boolean"}}, "required": []string{"target"}}},
	}
}

func textResult(text string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

// Serve melayani JSON-RPC dari stdin ke stdout sampai EOF.
func (s *Server) Serve() error {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	enc := json.NewEncoder(os.Stdout)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req rpcReq
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}
		resp := s.handle(req)
		if resp != nil {
			_ = enc.Encode(resp)
		}
	}
	return sc.Err()
}

func (s *Server) handle(req rpcReq) *rpcResp {
	isNotif := len(req.ID) == 0
	ok := func(result any) *rpcResp {
		if isNotif {
			return nil
		}
		return &rpcResp{JSONRPC: "2.0", ID: req.ID, Result: result}
	}
	fail := func(code int, msg string) *rpcResp {
		if isNotif {
			return nil
		}
		return &rpcResp{JSONRPC: "2.0", ID: req.ID, Error: &rpcErr{Code: code, Message: msg}}
	}
	switch req.Method {
	case "initialize":
		return ok(map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "xyland", "version": "0.5.0"},
		})
	case "ping":
		return ok(map[string]any{})
	case "tools/list":
		return ok(map[string]any{"tools": toolDefs()})
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return fail(-32602, "params tidak valid")
		}
		text, err := s.callTool(params.Name, params.Arguments)
		if err != nil {
			return fail(-32000, err.Error())
		}
		return ok(textResult(text))
	}
	return fail(-32601, "method tidak dikenal: "+req.Method)
}

func (s *Server) callTool(name string, args json.RawMessage) (string, error) {
	switch name {
	case "xyland_flow":
		var b strings.Builder
		for _, st := range engine.Order {
			br, err := engine.BriefOf(st)
			if err != nil {
				continue
			}
			fmt.Fprintf(&b, "%s — %s (gate: %s)\n", st, br.Goal, br.Gate)
		}
		return b.String(), nil
	case "xyland_skills":
		idx, err := skills.LoadIndex(s.SkillsDir)
		if err != nil {
			return "", err
		}
		var b strings.Builder
		for _, e := range idx.Skills {
			fmt.Fprintf(&b, "- %s: %s\n", e.Name, e.Description)
		}
		return b.String(), nil
	case "xyland_cves":
		cards, err := knowledge.LoadCards(s.CVEDir)
		if err != nil {
			return "", err
		}
		var b strings.Builder
		for _, c := range cards {
			fmt.Fprintf(&b, "- %s: %s\n", c.ID, c.Product)
		}
		return b.String(), nil
	case "xyland_scan":
		var a struct {
			Target string `json:"target"`
			DryRun bool   `json:"dry_run"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.Target == "" {
			return "", fmt.Errorf("argumen target wajib")
		}
		out := s.OutDir
		if out == "" {
			out = "results-mcp"
		}
		jobID, err := agent.Run(context.Background(), agent.Options{
			Target: a.Target, OutDir: out, DryRun: a.DryRun,
			SkillsDir: s.SkillsDir, CVEDir: s.CVEDir,
		})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("scan selesai: job %s — laporan di %s", jobID, filepath.Join(out, "report.md")), nil
	}
	return "", fmt.Errorf("tool tidak dikenal: %s", name)
}
