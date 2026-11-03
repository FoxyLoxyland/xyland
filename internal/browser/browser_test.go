package browser

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestConfirmSVGOnloadReal menjalankan browser sungguhan bila tersedia;
// di environment tanpa Chromium/libs, test di-skip (bukan gagal).
func TestConfirmSVGOnloadReal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>Results for: %s</body></html>", r.URL.Query().Get("q"))
	}))
	defer srv.Close()
	defer Close()
	payload := "xyland<svg onload=document.body.setAttribute('data-xyland','pwned')>"
	u := srv.URL + "/search?q=" + url.QueryEscape(payload)
	ok, shot, err := ConfirmSVGOnload(u)
	if err != nil {
		t.Skipf("browser tidak tersedia di environment ini: %v", err)
	}
	if !ok {
		t.Fatal("payload harus tereksekusi di DOM")
	}
	if len(shot) == 0 {
		t.Fatal("screenshot bukti harus ada saat eksekusi terkonfirmasi")
	}
	// kontrol negatif: tanpa payload, tidak ada eksekusi
	ok2, _, err2 := ConfirmSVGOnload(srv.URL + "/search?q=aman")
	if err2 == nil && ok2 {
		t.Fatal("kontrol negatif tidak boleh tereksekusi")
	}
}
