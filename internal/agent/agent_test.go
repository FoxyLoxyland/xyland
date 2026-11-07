package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// labServer: target rentan + jebakan, meniru lab uji manual v0.1 dan diperluas
// (SQLi error/boolean, traversal, CORS refleksi berkredensial).
func labServer(t *testing.T) *httptest.Server {
	t.Helper()
	spa := `<html><head><title>Lab Shop</title></head><body><h1>Lab</h1>welcome to the lab shop single page app</body></html>`
	mux := http.NewServeMux()
	uploads := map[string]string{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/uploads/") {
			w.WriteHeader(404)
			fmt.Fprint(w, "tidak ada")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/files/") {
			name := strings.TrimPrefix(r.URL.Path, "/files/")
			if c, ok := uploads[name]; ok {
				w.Header().Set("Content-Type", "image/svg+xml")
				fmt.Fprint(w, c)
			} else {
				w.WriteHeader(404)
				fmt.Fprint(w, "tidak ada")
			}
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		q := r.URL.Query()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Set-Cookie", "sid=abc; Path=/")
			fmt.Fprint(w, `<html><head><title>Lab Shop</title></head><body><h1>Lab</h1>`+
				`<a href="/search?q=test">s</a> <a href="/redirect?next=/home">r</a> `+
				`<a href="/item?id=1">i</a> <a href="/file?name=manual.txt">f</a> <a href="/profile?id=1">p</a> <a href="/fetch?url=http://example.local/">u</a> `+
				`<a href="/dom">d</a> <a href="/upload">up</a>`+
				`<form method="post" action="/settings"><input type="text" name="email"><input type="submit" value="simpan"></form></body></html>`)
		case "/.git/config":
			fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n")
		case "/.git/HEAD":
			fmt.Fprint(w, "ref: refs/heads/main\n")
		case "/.env":
			fmt.Fprint(w, spa) // jebakan SPA-200: bukan format .env
		case "/search":
			fmt.Fprintf(w, "<html><body>Results for: %s</body></html>", q.Get("q"))
		case "/item":
			id := q.Get("id")
			switch {
			case strings.Contains(id, "'"):
				fmt.Fprint(w, "Error: You have an error in your SQL syntax near '' at line 1")
			case strings.Contains(id, "AND 1=2"):
				fmt.Fprint(w, "<html><body>tidak ada hasil</body></html>")
			default:
				fmt.Fprint(w, "<html><body>Produk Sepatu XYZ — harga 100 — stok tersedia — deskripsi panjang produk</body></html>")
			}
		case "/file":
			if strings.Contains(q.Get("name"), "../") {
				fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
			} else {
				fmt.Fprint(w, "isi file manual biasa untuk pengguna")
			}
		case "/fetch":
			func() {
				cl := &http.Client{Timeout: 3 * time.Second}
				resp, err := cl.Get(q.Get("url"))
				if err == nil {
					resp.Body.Close()
				}
			}()
			fmt.Fprint(w, "fetch selesai")
		case "/profile":
			if q.Get("id") == "999999999" {
				fmt.Fprint(w, "pengguna tidak ditemukan")
			} else {
				fmt.Fprint(w, "Profil Pengguna Alice — email alice@lab.local — alamat Jalan Kenanga 12 — member sejak 2021 — status aktif")
			}
		case "/dom":
			fmt.Fprint(w, `<html><head><title>DOM</title></head><body><div id="x"></div><script>window.addEventListener("load",function(){var h=location.hash.slice(1);try{h=decodeURIComponent(h)}catch(e){} document.getElementById("x").innerHTML=h;});</script></body></html>`)
		case "/upload":
			if r.Method == "POST" {
				if err := r.ParseMultipartForm(1 << 20); err == nil {
					file, hdr, err := r.FormFile("file")
					if err == nil {
						defer file.Close()
						b, _ := io.ReadAll(file)
						uploads[hdr.Filename] = string(b)
						fmt.Fprintf(w, `<html><body>tersimpan: <a href="/files/%s">%s</a></body></html>`, hdr.Filename, hdr.Filename)
						return
					}
				}
				w.WriteHeader(400)
				fmt.Fprint(w, "gagal")
				return
			}
			fmt.Fprint(w, `<html><body><form method="post" action="/upload" enctype="multipart/form-data"><input type="file" name="file"><input type="submit" value="unggah"></form></body></html>`)
		case "/settings":
			fmt.Fprint(w, "tersimpan")
		case "/redirect":
			w.Header().Set("Location", q.Get("next"))
			w.WriteHeader(302)
		default:
			fmt.Fprint(w, spa)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestRunEndToEnd(t *testing.T) {
	t.Setenv("XYLAND_BROWSER", "off") // deterministik: konfirmasi browser diuji terpisah
	srv := labServer(t)
	out := t.TempDir()
	jobID, err := Run(context.Background(), Options{
		Target:    srv.URL,
		OutDir:    out,
		SkillsDir: filepath.Join("..", "..", "skills"),
		CVEDir:    filepath.Join("..", "..", "knowledge", "cve"),
	})
	if err != nil {
		t.Fatalf("run gagal: %v", err)
	}
	if jobID == "" {
		t.Fatal("jobID kosong")
	}
	// baca ledger hasil lewat store melalui file report
	report := filepath.Join(out, "report.md")
	_ = report

	// verifikasi temuan lewat DB
	st := openStore(t, out)
	findings, err := st.Findings(jobID)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]string{}
	for _, f := range findings {
		byKey[f.Class+"|"+f.URL] = f.Status
		if f.ExecutionID == 0 {
			t.Errorf("finding %s tanpa receipt execution_id", f.Title)
		}
	}
	base := srv.URL
	want := map[string]string{
		"exposure|" + base + "/.git/config":                "confirmed",
		"exposure|" + base + "/.env":                       "false-positive", // jebakan SPA harus tertolak
		"xss-reflected|" + base + "/search?q=test":         "likely",
		"open-redirect|" + base + "/redirect?next=/home":   "confirmed",
		"sqli|" + base + "/item?id=1":                      "confirmed",
		"path-traversal|" + base + "/file?name=manual.txt": "confirmed",
		"cors|" + base:                    "confirmed",
		"misconfig|" + base:               "confirmed",
		"csrf|" + base:                    "likely",
		"file-upload|" + base + "/upload": "confirmed",
	}
	for k, v := range want {
		if got := byKey[k]; got != v {
			t.Errorf("finding %s: status=%q, mau %q (semua: %v)", k, got, v, byKey)
		}
	}
	// finding confirmed/likely selain misconfig/cors harus punya PoC
	for _, f := range findings {
		if (f.Status == "confirmed" || f.Status == "likely") && f.Class != "misconfig" && f.Class != "cors" {
			if f.PocPath == "" {
				t.Errorf("finding %s (%s) tanpa PoC", f.Title, f.Status)
			}
		}
	}
	// cors PoC ada juga (generator mendukungnya)
	for _, f := range findings {
		if f.Class == "cors" && f.Status == "confirmed" && f.PocPath == "" {
			t.Errorf("cors confirmed tanpa PoC")
		}
	}
}
