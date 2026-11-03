// Package config memuat konfigurasi xyland dari file YAML (FR-07):
// LLM provider bisa diganti tanpa recompile. Env XYLAND_LLM_* menimpa file.
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LLM struct {
		BaseURL string `yaml:"base_url"`
		APIKey  string `yaml:"api_key"`
		Model   string `yaml:"model"`
	} `yaml:"llm"`
	Scan struct {
		Out string `yaml:"out"`
	} `yaml:"scan"`
}

// Load membaca file YAML; path kosong -> konfigurasi default (bukan error).
func Load(path string) (*Config, error) {
	cfg := &Config{}
	if path == "" {
		// cari default xyland.yaml di direktori kerja
		if _, err := os.Stat("xyland.yaml"); err == nil {
			path = "xyland.yaml"
		} else {
			return cfg, nil
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
