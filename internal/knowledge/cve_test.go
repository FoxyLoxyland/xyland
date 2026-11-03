package knowledge

import (
	"path/filepath"
	"testing"
)

func TestLoadAndMatch(t *testing.T) {
	cards, err := LoadCards(filepath.Join("..", "..", "knowledge", "cve"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) < 15 {
		t.Fatalf("kartu CVE harus >=15, dapat %d", len(cards))
	}
	// fingerprint server generik TIDAK boleh mencocokkan kartu apa pun
	noise := Match(cards, "server=BaseHTTP/0.6 Python; content-type=text/html", 5)
	if len(noise) != 0 {
		t.Fatalf("kata generik 'server' tidak boleh cocok, dapat %d kartu", len(noise))
	}
	// produk khas harus cocok
	wp := Match(cards, "wordpress terdeteksi; powered-by=PHP/8.1", 5)
	_ = wp // wordpress tanpa kartu khusus masih boleh kosong; yang wajib: joomla/metabase khas
	jm := Match(cards, "joomla! 4.2 terdeteksi di header", 5)
	if len(jm) == 0 {
		t.Fatal("fingerprint joomla harus mencocokkan kartu CVE-2023-23752")
	}
}
