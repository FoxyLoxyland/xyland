package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FoxyLoxyland/xyland/internal/store"
)

func TestDedupKeepsStrongestAndSorts(t *testing.T) {
	in := []store.Finding{
		{Class: "sqli", URL: "http://x/item?id=1", Severity: "high", Status: "likely"},
		{Class: "sqli", URL: "http://x/item?id=1/", Severity: "high", Status: "confirmed"},
		{Class: "cors", URL: "http://x", Severity: "low", Status: "confirmed"},
		{Class: "exposure", URL: "http://x/.env", Severity: "critical", Status: "false-positive"},
	}
	out := Dedup(in)
	if len(out) != 3 {
		t.Fatalf("dedup harus 3, dapat %d", len(out))
	}
	if out[0].Class != "sqli" || out[0].Status != "confirmed" {
		t.Fatalf("urutan/status triage salah: %+v", out[0])
	}
	if Priority(out[len(out)-1]) != 0 {
		t.Fatal("false-positive harus prioritas 0 (paling bawah)")
	}
}

func TestGenerateJSON(t *testing.T) {
	dir := t.TempDir()
	fs := []store.Finding{{Class: "exposure", Title: "Exposed", URL: "http://x/.git/config", Severity: "high", Status: "confirmed", Evidence: "marker", ExecutionID: 7}}
	p, err := GenerateJSON(dir, "job-1", "http://x", fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), `"execution_id": 7`) || !strings.Contains(string(raw), `"priority": 4`) {
		t.Fatalf("report.json tidak lengkap: %s", raw)
	}
	if filepath.Base(p) != "report.json" {
		t.Fatal("nama file salah")
	}
}

func TestChains(t *testing.T) {
	fs := []store.Finding{
		{Class: "xss-reflected", Status: "confirmed", Severity: "medium"},
		{Class: "misconfig", Status: "confirmed", Severity: "low", Evidence: "cookie-no-httponly=sid"},
		{Class: "exposure", Status: "false-positive", Severity: "high"},
	}
	chains := Chains(fs)
	if len(chains) != 1 || !strings.Contains(chains[0], "pencurian sesi") {
		t.Fatalf("chain XSS+cookie harus muncul tepat 1: %v", chains)
	}
	if len(Chains(nil)) != 0 {
		t.Fatal("tanpa finding tidak boleh ada saran chain")
	}
}
