package agent

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/FoxyLoxyland/xyland/internal/browser"
	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/store"
)

// checkDOMXSS: DOM XSS berbasis fragment (#) dibuktikan dengan eksekusi nyata
// di browser (knowledge/validation/xss-dom.yaml). Payload ter-percent-encode
// di fragment; sink DOM yang umum (innerHTML = decodeURIComponent(location.hash))
// akan mengeksekusinya dan memasang marker data-xyland pada body.
// Dipakai ulang executor browser yang sama dengan konfirmasi reflected XSS.
func checkDOMXSS(opts Options, st *store.Store, jobID string, pages []string) {
	if !browser.Enabled() {
		return
	}
	payload := `<img src=x onerror=document.body.setAttribute('data-xyland','pwned')>`
	frag := "#" + strings.ReplaceAll(url.PathEscape(payload), "%2F", "/")
	seen := map[string]bool{}
	n := 0
	for _, pg := range pages {
		if n >= 3 {
			break
		}
		clean := strings.Split(pg, "#")[0]
		if seen[clean] {
			continue
		}
		seen[clean] = true
		testURL := clean + frag
		execID, _ := st.RecordExecution(jobID, "check/xss-dom", testURL, 0, "payload fragment + eksekusi browser, repeat 2")
		hits := 0
		var lastShot []byte
		for i := 0; i < 2; i++ {
			exec, shot, err := browser.ConfirmSVGOnload(testURL)
			if err != nil {
				emit(opts, engine.StateVerdict, "warn", "xss-dom: browser executor gagal: "+err.Error())
				return
			}
			if exec {
				hits++
				lastShot = shot
			}
		}
		if hits == 0 {
			continue
		}
		n++
		status := "inconclusive"
		evidence := "payload fragment tereksekusi 1/2 run di browser — tidak stabil"
		if hits == 2 {
			status = "confirmed"
			evidence = "payload pada fragment (#) dieksekusi di DOM browser nyata 2/2 run (handler memasang marker data-xyland) — sumber fragment mengalir ke sink DOM tanpa sanitasi"
		}
		if status == "confirmed" && len(lastShot) > 0 {
			dir := filepath.Join(opts.OutDir, "evidence")
			_ = os.MkdirAll(dir, 0o755)
			sp := filepath.Join(dir, "xss-dom-"+itoa(n)+".png")
			if os.WriteFile(sp, lastShot, 0o644) == nil {
				evidence += "; screenshot bukti: " + sp
			}
		}
		_, _ = st.AddFinding(store.Finding{JobID: jobID, Class: "xss-dom", Title: "DOM-based XSS (fragment sink)", URL: clean, Severity: "high", Status: status, Evidence: evidence, ExecutionID: execID})
		emit(opts, engine.StateVerdict, "verdict", "xss-dom "+clean+" -> "+status)
	}
}
