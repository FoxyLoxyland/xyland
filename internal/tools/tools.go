// Package tools berisi prober HTTP bawaan (selalu tersedia) dan runner
// untuk binary eksternal ProjectDiscovery bila terpasang di PATH.
// Setiap eksekusi dicatat pemanggil ke store sebagai receipt.
package tools

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type ProbeResult struct {
	URL         string
	StatusCode  int
	Title       string
	Headers     http.Header
	Body        string
	BodyHash    string
	Links       []string // href mentah dari body (untuk penemuan parameter)
	ContentType string
}

var (
	titleRe = regexp.MustCompile(`(?is)<title>(.*?)</title>`)
	hrefRe  = regexp.MustCompile(`(?i)href\s*=\s*"([^"]+)"|href\s*=\s*'([^']+)'`)
)

func NewClient() *http.Client {
	return &http.Client{
		Timeout: 12 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // jangan ikuti redirect: kita perlu melihatnya
		},
	}
}

// Fetch mengambil satu URL tanpa mengikuti redirect.
func Fetch(ctx context.Context, hc *http.Client, rawurl string) (*ProbeResult, error) {
	return FetchWithHeaders(ctx, hc, rawurl, nil)
}

// FetchWithHeaders seperti Fetch, dengan header tambahan (mis. Origin untuk CORS).
func FetchWithHeaders(ctx context.Context, hc *http.Client, rawurl string, extra map[string]string) (*ProbeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xyland/0.1 (authorized security research)")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	sum := sha256.Sum256(b)
	pr := &ProbeResult{
		URL: rawurl, StatusCode: resp.StatusCode, Headers: resp.Header,
		Body: string(b), BodyHash: fmt.Sprintf("%x", sum[:8]),
		ContentType: resp.Header.Get("Content-Type"),
	}
	if m := titleRe.FindStringSubmatch(pr.Body); m != nil {
		pr.Title = strings.TrimSpace(m[1])
	}
	for _, m := range hrefRe.FindAllStringSubmatch(pr.Body, -1) {
		link := m[1]
		if link == "" {
			link = m[2]
		}
		if link != "" {
			pr.Links = append(pr.Links, link)
		}
	}
	return pr, nil
}

// Fingerprint meringkas hasil probe menjadi teks fingerprint terstruktur.
func Fingerprint(pr *ProbeResult) string {
	var parts []string
	if s := pr.Headers.Get("Server"); s != "" {
		parts = append(parts, "server="+s)
	}
	if s := pr.Headers.Get("X-Powered-By"); s != "" {
		parts = append(parts, "powered-by="+s)
	}
	parts = append(parts, "content-type="+pr.ContentType)
	var missing []string
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"} {
		if pr.Headers.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		parts = append(parts, "missing-headers="+strings.Join(missing, ","))
	}
	for _, c := range pr.Headers.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		name := strings.SplitN(c, "=", 2)[0]
		if !strings.Contains(lc, "httponly") {
			parts = append(parts, "cookie-no-httponly="+name)
		}
		if !strings.Contains(lc, "secure") {
			parts = append(parts, "cookie-no-secure="+name)
		}
		if !strings.Contains(lc, "samesite") {
			parts = append(parts, "cookie-no-samesite="+name)
		}
	}
	if strings.Contains(pr.Body, "wp-content") {
		parts = append(parts, "wordpress")
	}
	if strings.Contains(strings.ToLower(pr.Body), "graphql") {
		parts = append(parts, "graphql")
	}
	return strings.Join(parts, "; ")
}

// ExternalAvailable memeriksa binary eksternal di PATH.
func ExternalAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// RunExternal menjalankan binary eksternal dengan argumen, mengembalikan ringkasan output.
func RunExternal(ctx context.Context, name string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return "", -1, err
		}
	}
	s := string(out)
	if len(s) > 4000 {
		s = s[:4000]
	}
	return s, code, nil
}
