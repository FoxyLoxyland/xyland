// Package skills memuat library skill xyland dengan progressive disclosure:
// L1 = _index.yaml (selalu tersedia), L2 = SKILL.md (hanya saat terpilih),
// L3 = references/ (hanya saat langkah membutuhkannya). Lihat docs/12 & 13.
package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Entry struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Triggers    map[string]any `yaml:"triggers"`
	SafetyLevel int            `yaml:"safety_level"`
	ContextCost int            `yaml:"context_cost"`
}

type Index struct {
	Version int     `yaml:"version"`
	Skills  []Entry `yaml:"skills"`
}

func LoadIndex(dir string) (*Index, error) {
	b, err := os.ReadFile(filepath.Join(dir, "_index.yaml"))
	if err != nil {
		return nil, err
	}
	var idx Index
	if err := yaml.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("parse skills index: %w", err)
	}
	return &idx, nil
}

// triggerValues meratakan nilai trigger (string / []any) menjadi daftar string kecil.
func triggerValues(e Entry) []string {
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, strings.ToLower(t))
		case []any:
			for _, x := range t {
				walk(x)
			}
		}
	}
	for _, v := range e.Triggers {
		walk(v)
	}
	return out
}

// Select memilih maks `max` skill yang trigger/fingerprint-nya cocok dengan tags,
// diurutkan dari yang paling banyak cocok. Ini retrieval deterministik (P-4):
// model menerima kandidat ini, bukan mencari sendiri di seluruh library.
func (idx *Index) Select(tags []string, phase string, max int) []Entry {
	tagset := map[string]bool{}
	for _, t := range tags {
		tagset[strings.ToLower(t)] = true
	}
	if phase != "" {
		tagset[strings.ToLower(phase)] = true
	}
	type scored struct {
		e     Entry
		score int
	}
	var all []scored
	for _, e := range idx.Skills {
		sc := 0
		for _, tv := range triggerValues(e) {
			if tagset[tv] {
				sc++
			}
			// kecocokan parsial untuk fingerprint gabungan, mis "text/html" dalam "content-type:text/html"
			for t := range tagset {
				if strings.Contains(tv, t) || strings.Contains(t, tv) {
					sc++
				}
			}
		}
		if sc > 0 {
			all = append(all, scored{e, sc})
		}
	}
	// urut sederhana: skor desc, lalu context_cost asc (efisiensi konteks)
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].score > all[i].score || (all[j].score == all[i].score && all[j].e.ContextCost < all[i].e.ContextCost) {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	var out []Entry
	for i, s := range all {
		if i >= max {
			break
		}
		out = append(out, s.e)
	}
	return out
}

// LoadBody memuat isi L2 sebuah skill (dipanggil hanya untuk skill terpilih).
func LoadBody(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name, "SKILL.md"))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
