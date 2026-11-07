package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FoxyLoxyland/xyland/internal/browser"
)

func makeJWT(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	msg := enc(map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + enc(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	return msg + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Server "API" yang rentan JWT: menerima alg=none DAN token bertanda "secret".
func jwtLabServer(t *testing.T) *httptest.Server {
	t.Helper()
	secretBody := "PANEL RAHASIA: daftar pengguna admin lab — data internal yang panjang untuk membedakan respons terautentikasi dari penolakan"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(tok, ".")
		if len(parts) == 3 {
			hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
			var hdr map[string]any
			_ = json.Unmarshal(hb, &hdr)
			if hdr["alg"] == "none" {
				fmt.Fprint(w, secretBody)
				return
			}
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			mac := hmac.New(sha256.New, []byte("secret"))
			mac.Write([]byte(parts[0] + "." + parts[1]))
			if hmac.Equal(mac.Sum(nil), sig) {
				fmt.Fprint(w, secretBody)
				return
			}
		}
		w.WriteHeader(401)
		fmt.Fprint(w, "unauthorized — silakan login terlebih dahulu untuk melihat panel ini")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestJWTChecks(t *testing.T) {
	t.Setenv("XYLAND_BROWSER", "off")
	srv := jwtLabServer(t)
	tok := makeJWT(t, "secret", map[string]any{"sub": "1", "role": "admin"}) // tanpa exp juga
	out := t.TempDir()
	jobID, err := Run(context.Background(), Options{
		Target: srv.URL, OutDir: out, JWT: tok,
		SkillsDir: filepath.Join("..", "..", "skills"), CVEDir: filepath.Join("..", "..", "knowledge", "cve"),
	})
	if err != nil {
		t.Fatal(err)
	}
	st := openStore(t, out)
	findings, _ := st.Findings(jobID)
	confirmed := 0
	likely := 0
	for _, f := range findings {
		if f.Class != "jwt" {
			continue
		}
		if f.Status == "confirmed" {
			confirmed++
		}
		if f.Status == "likely" {
			likely++
		}
		if f.PocPath == "" {
			t.Errorf("finding jwt %q tanpa PoC", f.Title)
		}
	}
	// minimal: secret lemah (confirmed) + alg=none diterima (confirmed)
	if confirmed < 2 {
		t.Fatalf("jwt confirmed=%d, mau >=2 (semua: %+v)", confirmed, findings)
	}
	if likely < 1 {
		t.Fatalf("jwt likely (higiene klaim, tanpa exp) harus ada")
	}
}

func TestDOMXSSBrowser(t *testing.T) {
	srv := labServer(t)
	if _, err := browser.ScreenshotURL(srv.URL); err != nil {
		t.Skip("chromium tidak tersedia:", err)
	}
	out := t.TempDir()
	jobID, err := Run(context.Background(), Options{
		Target: srv.URL, OutDir: out,
		SkillsDir: filepath.Join("..", "..", "skills"), CVEDir: filepath.Join("..", "..", "knowledge", "cve"),
	})
	if err != nil {
		t.Fatal(err)
	}
	st := openStore(t, out)
	findings, _ := st.Findings(jobID)
	found := ""
	for _, f := range findings {
		if f.Class == "xss-dom" {
			found = f.Status
		}
	}
	if found != "confirmed" {
		t.Fatalf("xss-dom status=%q, mau confirmed", found)
	}
}
