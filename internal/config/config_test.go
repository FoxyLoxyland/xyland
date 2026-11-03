package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "xyland.yaml")
	if err := os.WriteFile(p, []byte("llm:\n  base_url: \"http://localhost:20128/v1\"\n  model: \"m1\"\nscan:\n  out: \"hasil\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.BaseURL != "http://localhost:20128/v1" || cfg.LLM.Model != "m1" || cfg.Scan.Out != "hasil" {
		t.Fatalf("config salah parse: %+v", cfg)
	}
}

func TestLoadMissingDefaultOK(t *testing.T) {
	cfg, err := Load("")
	if err != nil || cfg == nil {
		t.Fatalf("tanpa file harus default kosong tanpa error: %v", err)
	}
}
