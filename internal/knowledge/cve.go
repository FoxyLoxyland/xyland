// Package knowledge memuat kartu CVE terkurasi (docs/13) dan mencocokkannya
// ke fingerprint target. Kartu hanya boleh diklaim bila prasyarat fingerprint
// terverifikasi — pencocokan di sini menghasilkan KANDIDAT, bukan klaim.
package knowledge

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Card struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	Product string `yaml:"product"`
	File    string // diisi loader
	Raw     string // isi mentah kartu (untuk konteks agent, terpotong sesuai budget)
}

type cveIndex struct {
	Cards []struct {
		ID      string `yaml:"id"`
		Product string `yaml:"product"`
		File    string `yaml:"file"`
	} `yaml:"cards"`
}

func LoadCards(dir string) ([]Card, error) {
	b, err := os.ReadFile(filepath.Join(dir, "_index.yaml"))
	if err != nil {
		return nil, err
	}
	var idx cveIndex
	if err := yaml.Unmarshal(b, &idx); err != nil {
		return nil, err
	}
	var out []Card
	for _, c := range idx.Cards {
		raw, _ := os.ReadFile(filepath.Join(dir, c.File))
		out = append(out, Card{ID: c.ID, Product: c.Product, File: c.File, Raw: string(raw)})
	}
	return out, nil
}

// Match mengembalikan kartu yang nama produknya muncul di teks fingerprint.
// Kata kunci produk diambil dari field product kartu (token >= 4 huruf yang khas).
func Match(cards []Card, fingerprintText string, max int) []Card {
	hay := strings.ToLower(fingerprintText)
	generic := map[string]bool{"server": true, "windows": true, "data": true, "center": true, "cloud": true, "microsoft": true}
	var out []Card
	for _, c := range cards {
		prod := strings.ToLower(c.Product)
		hit := false
		for _, tok := range strings.FieldsFunc(prod, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
		}) {
			if len(tok) >= 6 && !generic[tok] && strings.Contains(hay, tok) {
				hit = true
				break
			}
		}
		// nama khas produk dua kata, mis "moveit", "log4j", "confluence", "wordpress", "joomla", "metabase", "teamcity", "superset", "spring", "laravel", "php", "exchange", "citrix", "netscaler"
		for _, kw := range []string{"log4j", "moveit", "confluence", "wordpress", "joomla", "metabase", "teamcity", "superset", "laravel", "citrix", "netscaler", "exchange"} {
			if strings.Contains(prod, kw) && strings.Contains(hay, kw) {
				hit = true
			}
		}
		if hit {
			out = append(out, c)
			if len(out) >= max {
				break
			}
		}
	}
	return out
}
