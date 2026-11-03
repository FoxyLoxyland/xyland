package validate

import "testing"

func TestSimilarity(t *testing.T) {
	same := Similarity("halo dunia lab shop", "halo dunia lab shop")
	if same != 1 {
		t.Fatalf("body identik harus 1, dapat %v", same)
	}
	diff := Similarity("halo dunia lab shop selamat datang", "root:x:0:0: bin:x:1:1: daemon")
	if diff > 0.5 {
		t.Fatalf("body sangat berbeda harus rendah, dapat %v", diff)
	}
	near := Similarity("produk sepatu harga 100 tersedia stok", "produk sepatu harga 100 tersedia stok!")
	if near < 0.8 {
		t.Fatalf("body nyaris sama harus tinggi, dapat %v", near)
	}
}
