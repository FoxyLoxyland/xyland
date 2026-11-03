package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"strings"

	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/scope"
	"github.com/FoxyLoxyland/xyland/internal/store"
	"github.com/FoxyLoxyland/xyland/internal/tools"
)

// --- parser murni (diuji unit) ---

type httpxResult struct {
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Tech       []string `json:"tech"`
	Host       string   `json:"host"`
}

func parseHttpxJSONL(out string) []httpxResult {
	var res []httpxResult
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r httpxResult
		if json.Unmarshal([]byte(line), &r) == nil && r.URL != "" {
			res = append(res, r)
		}
	}
	return res
}

func parseSubfinderLines(out string) []string {
	var res []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		h := strings.TrimSpace(strings.ToLower(line))
		if h == "" || seen[h] || strings.Contains(h, " ") {
			continue
		}
		seen[h] = true
		res = append(res, h)
	}
	return res
}

func isDomainHost(host string) bool {
	if host == "localhost" || net.ParseIP(host) != nil {
		return false
	}
	return strings.Contains(host, ".")
}

// enrichRecon menjalankan tool eksternal bila tersedia (spec §4 MVP):
// httpx untuk probing/fingerprint tambahan, subfinder untuk subdomain.
// Semua hasil tercatat sebagai receipt; kegagalan tool tidak menghentikan flow.
func enrichRecon(ctx context.Context, opts Options, st *store.Store, jobID string, sc *scope.Scope) {
	hc := tools.NewClient()
	target := opts.Target
	u, _ := url.Parse(target)
	host := ""
	if u != nil {
		host = u.Hostname()
	}

	if tools.ExternalAvailable("httpx") {
		out, code, err := tools.RunExternal(ctx, "httpx", "-silent", "-json", "-status-code", "-title", "-tech-detect", "-u", target)
		execID, _ := st.RecordExecution(jobID, "httpx", target, code, "eksternal via PATH")
		if err == nil {
			for _, r := range parseHttpxJSONL(out) {
				fp := "httpx"
				if len(r.Tech) > 0 {
					fp += "; tech=" + strings.Join(r.Tech, ",")
				}
				if r.URL != target && sc.Allows(r.URL) {
					_, _ = st.AddAsset(store.Asset{JobID: jobID, URL: r.URL, StatusCode: r.StatusCode, Title: r.Title, Fingerprint: fp, ExecutionID: execID})
				}
				emit(opts, engine.StateRecon, "tool", "httpx: "+r.URL+" tech="+strings.Join(r.Tech, ","))
			}
		}
	}

	if tools.ExternalAvailable("subfinder") && isDomainHost(host) {
		out, code, err := tools.RunExternal(ctx, "subfinder", "-silent", "-d", host)
		execID, _ := st.RecordExecution(jobID, "subfinder", host, code, "eksternal via PATH")
		if err == nil {
			subs := parseSubfinderLines(out)
			emit(opts, engine.StateRecon, "tool", "subfinder: "+itoa(len(subs))+" subdomain kandidat")
			probed := 0
			for _, sub := range subs {
				if probed >= 15 {
					break
				}
				cand := "https://" + sub
				if !sc.Allows(cand) || sub == host {
					continue
				}
				pr, err := tools.Fetch(ctx, hc, cand)
				if err != nil {
					continue
				}
				probed++
				_, _ = st.AddAsset(store.Asset{JobID: jobID, URL: cand, StatusCode: pr.StatusCode, Title: pr.Title, Fingerprint: tools.Fingerprint(pr), ExecutionID: execID})
				emit(opts, engine.StateRecon, "tool", "subdomain hidup: "+cand)
			}
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	d := ""
	for n > 0 {
		d = string(rune('0'+n%10)) + d
		n /= 10
	}
	return d
}
