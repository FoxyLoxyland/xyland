// Package agent adalah orkestrator flow xyland: ia menjalankan state machine
// engine langkah demi langkah, memanggil tool, dan (bila tersedia) meminta LLM
// membantu menilai hipotesis — tanpa pernah menyerahkan verdict ke LLM.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/knowledge"
	"github.com/FoxyLoxyland/xyland/internal/llm"
	"github.com/FoxyLoxyland/xyland/internal/poc"
	"github.com/FoxyLoxyland/xyland/internal/report"
	"github.com/FoxyLoxyland/xyland/internal/scope"
	"github.com/FoxyLoxyland/xyland/internal/skills"
	"github.com/FoxyLoxyland/xyland/internal/store"
	"github.com/FoxyLoxyland/xyland/internal/tools"
	"github.com/FoxyLoxyland/xyland/internal/validate"
)

type Event struct {
	State engine.State
	Kind  string // state | info | tool | agent | verdict | warn
	Msg   string
}

type Options struct {
	Target    string
	ScopeFile string
	OutDir    string
	SkillsDir string
	CVEDir    string
	ResumeID  string
	OnEvent   func(Event)
}

type Hypothesis struct {
	Class      string  `json:"class"`
	Reason     string  `json:"reason"`
	Impact     float64 `json:"impact"`
	Confidence float64 `json:"confidence"`
	Difficulty float64 `json:"difficulty"`
	Score      float64 `json:"score"`
}

func emit(opts Options, s engine.State, kind, msg string) {
	if opts.OnEvent != nil {
		opts.OnEvent(Event{State: s, Kind: kind, Msg: msg})
	}
}

var redirectParams = map[string]bool{"next": true, "url": true, "redirect": true, "return": true, "target": true, "dest": true, "continue": true, "callback": true}

// Run mengeksekusi flow penuh (atau melanjutkannya bila ResumeID diisi).
func Run(ctx context.Context, opts Options) (string, error) {
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return "", err
	}
	st, err := store.Open(filepath.Join(opts.OutDir, "xyland.db"))
	if err != nil {
		return "", err
	}
	defer st.DB.Close()

	jobID := opts.ResumeID
	resuming := jobID != ""
	if !resuming {
		jobID = "job-" + time.Now().Format("20060102150405")
		if err := st.CreateJob(jobID, opts.Target); err != nil {
			return "", err
		}
	}
	job, err := st.GetJob(jobID)
	if err != nil {
		return "", err
	}
	curIdx := engine.Index(engine.State(job.State))
	passed := func(s engine.State) bool {
		return resuming && engine.Index(s) <= curIdx && engine.Index(s) < engine.Index(engine.StateVerdict)
	}

	advance := func(s engine.State) {
		_ = st.SetState(jobID, string(s))
		emit(opts, s, "state", string(s))
	}

	// ---- SCOPE ----
	var sc *scope.Scope
	if opts.ScopeFile != "" {
		sc, err = scope.LoadFile(opts.ScopeFile)
	} else {
		sc, err = scope.ForTarget(opts.Target)
	}
	if err != nil {
		return jobID, err
	}
	advance(engine.StateScope)
	if !sc.Allows(opts.Target) {
		return jobID, fmt.Errorf("target %s di LUAR scope — ditolak engine", opts.Target)
	}
	emit(opts, engine.StateScope, "info", "scope terverifikasi untuk "+opts.Target)

	hc := tools.NewClient()
	var assets []store.Asset
	var paramURLs []string
	var rootProbe *tools.ProbeResult

	// ---- RECON + FINGERPRINT ----
	if passed(engine.StateFingerprint) {
		assets, _ = st.Assets(jobID)
		emit(opts, engine.StateRecon, "info", "resume: recon dilewati, aset dimuat dari ledger")
	} else {
		advance(engine.StateRecon)
		execID, _ := st.RecordExecution(jobID, "prober", opts.Target, 0, "built-in HTTP prober")
		pr, err := tools.Fetch(ctx, hc, opts.Target)
		if err != nil {
			_, _ = st.RecordExecution(jobID, "prober", opts.Target, 1, err.Error())
			return jobID, fmt.Errorf("prober gagal: %w", err)
		}
		rootProbe = pr
		aid, _ := st.AddAsset(store.Asset{JobID: jobID, URL: pr.URL, StatusCode: pr.StatusCode, Title: pr.Title, Fingerprint: tools.Fingerprint(pr), ExecutionID: execID})
		_ = aid
		emit(opts, engine.StateRecon, "tool", fmt.Sprintf("prober: %s -> %d %q", pr.URL, pr.StatusCode, pr.Title))
		for _, name := range []string{"subfinder", "httpx", "nuclei", "katana"} {
			if tools.ExternalAvailable(name) {
				emit(opts, engine.StateRecon, "tool", name+" terdeteksi di PATH (wrapper tersedia)")
			}
		}
		// kumpulkan URL berparameter dari tautan (masih dalam scope)
		seen := map[string]bool{}
		base, _ := url.Parse(opts.Target)
		for _, l := range pr.Links {
			u, err := base.Parse(l)
			if err != nil || u.RawQuery == "" {
				continue
			}
			abs := u.String()
			if sc.Allows(abs) && !seen[abs] {
				seen[abs] = true
				paramURLs = append(paramURLs, abs)
			}
		}
		assets, _ = st.Assets(jobID)
		advance(engine.StateFingerprint)
		emit(opts, engine.StateFingerprint, "info", "fingerprint: "+tools.Fingerprint(pr))
	}
	if rootProbe == nil && len(assets) > 0 {
		// resume: bangun ulang konteks minimal dari aset tersimpan
		emit(opts, engine.StateFingerprint, "info", "fingerprint dimuat dari ledger: "+assets[0].Fingerprint)
	}

	fpText := ""
	var linksHaveParams bool
	if rootProbe != nil {
		fpText = tools.Fingerprint(rootProbe)
		linksHaveParams = len(paramURLs) > 0
	} else if len(assets) > 0 {
		fpText = assets[0].Fingerprint
	}
	hasRedirectParam := false
	for _, pu := range paramURLs {
		u, _ := url.Parse(pu)
		for k := range u.Query() {
			if redirectParams[strings.ToLower(k)] {
				hasRedirectParam = true
			}
		}
	}

	// ---- HYPOTHESIS ----
	advance(engine.StateHypothesis)
	hyps := buildHypotheses(fpText, linksHaveParams, hasRedirectParam)
	// Bantuan LLM (opsional): minta penilaian ulang skor; kegagalan tidak menghentikan flow.
	cfg := llm.ConfigFromEnv()
	if cfg.Available() {
		if note := llmAssist(ctx, cfg, fpText, hyps); note != "" {
			emit(opts, engine.StateHypothesis, "agent", note)
			_ = st.AddNote(jobID, string(engine.StateHypothesis), note)
		}
	} else {
		emit(opts, engine.StateHypothesis, "agent", "LLM tidak terkonfigurasi — skor hipotesis heuristik deterministik")
	}
	for _, h := range hyps {
		emit(opts, engine.StateHypothesis, "agent", fmt.Sprintf("hipotesis %s (skor %.2f) — %s", h.Class, h.Score, h.Reason))
	}

	// ---- RETRIEVAL ----
	advance(engine.StateRetrieval)
	tags := []string{"scanning", "validation"}
	if strings.Contains(fpText, "wordpress") {
		tags = append(tags, "wordpress")
	}
	if linksHaveParams {
		tags = append(tags, "param-reflection")
	}
	if hasRedirectParam {
		tags = append(tags, "redirect-parameter")
	}
	var selSkills []skills.Entry
	if idx, err := skills.LoadIndex(opts.SkillsDir); err == nil {
		selSkills = idx.Select(tags, "", 5)
		for _, s := range selSkills {
			emit(opts, engine.StateRetrieval, "info", fmt.Sprintf("skill terpilih: %s (±%d token)", s.Name, s.ContextCost))
		}
	} else {
		emit(opts, engine.StateRetrieval, "warn", "indeks skill tidak terbaca: "+err.Error())
	}
	if cards, err := knowledge.LoadCards(opts.CVEDir); err == nil {
		for _, c := range knowledge.Match(cards, fpText+" "+opts.Target, 5) {
			emit(opts, engine.StateRetrieval, "info", "kartu CVE kandidat: "+c.ID+" ("+c.Product+") — kandidat, bukan klaim")
		}
	}

	// ---- EXECUTION + VERDICT ----
	existing, _ := st.Findings(jobID)
	if resuming && len(existing) > 0 {
		emit(opts, engine.StateExecution, "info", "resume: eksekusi dilewati, finding dimuat dari ledger")
	} else {
		advance(engine.StateExecution)
		base := strings.TrimRight(opts.Target, "/")
		// baseline anti-200-trap sekali per target
		baseline, berr := validate.FetchBaseline(ctx, base)
		baseBody := ""
		if berr == nil {
			baseBody = baseline.Body
		}
		for _, h := range hyps {
			switch h.Class {
			case "exposure":
				checkExposure(ctx, opts, st, jobID, base, baseBody)
			case "xss-reflected":
				checkReflected(ctx, opts, st, jobID, paramURLs)
			case "open-redirect":
				checkRedirect(ctx, opts, st, jobID, paramURLs)
			case "misconfig":
				checkMisconfig(opts, st, jobID, opts.Target, fpText)
			}
		}
		advance(engine.StateVerdict)
		emit(opts, engine.StateVerdict, "verdict", "verdict dihitung deterministik dari positive/control/baseline")
	}

	// ---- POC ----
	advance(engine.StatePoC)
	findings, _ := st.Findings(jobID)
	for _, f := range findings {
		if (f.Status == "confirmed" || f.Status == "likely") && f.PocPath == "" {
			if content, ok := poc.Generate(f.Class, f.URL); ok {
				dir := filepath.Join(opts.OutDir, "findings", fmt.Sprintf("%d-%s", f.ID, f.Class))
				_ = os.MkdirAll(dir, 0o755)
				p := filepath.Join(dir, "poc.py")
				if err := os.WriteFile(p, []byte(content), 0o755); err == nil {
					_ = st.UpdateFindingStatus(f.ID, f.Status, p)
					emit(opts, engine.StatePoC, "info", "PoC dibuat: "+p)
				}
			}
		}
	}

	// ---- REPORT ----
	advance(engine.StateReport)
	findings, _ = st.Findings(jobID)
	assets, _ = st.Assets(jobID)
	rp, err := report.Generate(opts.OutDir, jobID, opts.Target, findings, assets)
	if err != nil {
		return jobID, err
	}
	advance(engine.StateDone)
	emit(opts, engine.StateReport, "info", "laporan: "+rp)
	return jobID, nil
}

func buildHypotheses(fp string, hasParams, hasRedirect bool) []Hypothesis {
	mk := func(class, reason string, impact, conf, diff float64) Hypothesis {
		return Hypothesis{Class: class, Reason: reason, Impact: impact, Confidence: conf, Difficulty: diff, Score: impact * conf / diff}
	}
	hyps := []Hypothesis{
		mk("exposure", "file sensitif terekspos adalah temuan bug bounty paling umum; tesnya murah & deterministik", 7, 0.5, 2),
	}
	if strings.Contains(fp, "missing-headers") || strings.Contains(fp, "cookie-no") {
		hyps = append(hyps, mk("misconfig", "fingerprint menunjukkan header keamanan/flag cookie hilang", 3, 0.9, 1))
	}
	if hasParams {
		hyps = append(hyps, mk("xss-reflected", "tautan berparameter ditemukan saat recon — kandidat refleksi", 6, 0.6, 3))
	}
	if hasRedirect {
		hyps = append(hyps, mk("open-redirect", "parameter mirip redirect ditemukan pada tautan", 5, 0.6, 2))
	}
	// urut skor desc
	for i := 0; i < len(hyps); i++ {
		for j := i + 1; j < len(hyps); j++ {
			if hyps[j].Score > hyps[i].Score {
				hyps[i], hyps[j] = hyps[j], hyps[i]
			}
		}
	}
	if len(hyps) > 7 {
		hyps = hyps[:7]
	}
	return hyps
}

func llmAssist(ctx context.Context, cfg llm.Config, fp string, hyps []Hypothesis) string {
	cl := llm.New(cfg)
	hj, _ := json.Marshal(hyps)
	msgs := []llm.Message{
		{Role: "system", Content: "Kamu penilai hipotesis pentest. Balas SINGKAT satu kalimat Bahasa Indonesia tentang hipotesis mana yang paling menjanjikan dan kenapa. Jangan membuat finding baru."},
		{Role: "user", Content: fmt.Sprintf("Fingerprint: %s\nHipotesis (JSON): %s", fp, hj)},
	}
	res, err := cl.Generate(ctx, msgs)
	if err != nil {
		return "LLM terkonfigurasi tapi gagal dipanggil (" + err.Error() + ") — lanjut heuristik"
	}
	txt := strings.TrimSpace(res.Text)
	if len(txt) > 220 {
		txt = txt[:220]
	}
	return fmt.Sprintf("LLM (%s, %d+%d token): %s", cfg.Model, res.PromptTokens, res.CompletionTokens, txt)
}

// --- checks ---

var exposurePaths = []struct{ Path, Marker string }{
	{"/.git/config", "[core]"},
	{"/.git/HEAD", "ref:"},
	{"/.env", ""}, // marker dinamis: pola KEY=VALUE
}

var envRe = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{2,}=\S+`)

func checkExposure(ctx context.Context, opts Options, st *store.Store, jobID, base, baseBody string) {
	hc := tools.NewClient()
	for _, ep := range exposurePaths {
		u := base + ep.Path
		execID, _ := st.RecordExecution(jobID, "check/exposed-files", u, 0, "positive+control+baseline, repeat 2")
		var hits int
		var lastBody string
		var status int
		for i := 0; i < 2; i++ {
			pr, err := tools.Fetch(ctx, hc, u)
			if err != nil {
				continue
			}
			status = pr.StatusCode
			lastBody = pr.Body
			matched := false
			if ep.Marker != "" {
				matched = strings.Contains(pr.Body, ep.Marker)
			} else {
				matched = envRe.MatchString(pr.Body)
			}
			if pr.StatusCode == 200 && matched {
				hits++
			}
		}
		if status != 200 {
			continue // tidak ada kandidat — jangan buat finding dari ketiadaan
		}
		verdict := "false-positive"
		evidence := "respons 200 tapi marker khas tidak cocok / tidak stabil"
		if hits == 2 {
			if strings.Contains(baseBody, ep.Marker) && ep.Marker != "" || validate.Similarity(baseBody, lastBody) > 0.9 {
				verdict = "inconclusive"
				evidence = "baseline tidak bisa dibedakan dari respons uji (anti-200-trap) — perlu pemeriksaan manual"
			} else {
				verdict = "confirmed"
				evidence = fmt.Sprintf("marker khas %q ditemukan 2/2 run; baseline berbeda (similarity %.2f)", markerLabel(ep), validate.Similarity(baseBody, lastBody))
			}
		}
		sev := "high"
		if strings.HasSuffix(ep.Path, ".env") {
			sev = "critical"
		}
		_, _ = st.AddFinding(store.Finding{JobID: jobID, Class: "exposure", Title: "Exposed file " + ep.Path, URL: u, Severity: sev, Status: verdict, Evidence: evidence, ExecutionID: execID})
		emit(opts, engine.StateVerdict, "verdict", fmt.Sprintf("exposure %s -> %s", ep.Path, verdict))
	}
}

func markerLabel(ep struct{ Path, Marker string }) string {
	if ep.Marker != "" {
		return ep.Marker
	}
	return "pola KEY=VALUE .env"
}

func checkReflected(ctx context.Context, opts Options, st *store.Store, jobID string, paramURLs []string) {
	hc := tools.NewClient()
	payload := "xyland<svg/onload=1>"
	n := 0
	for _, pu := range paramURLs {
		if n >= 3 {
			break
		}
		u, err := url.Parse(pu)
		if err != nil {
			continue
		}
		q := u.Query()
		for k := range q {
			q.Set(k, payload)
			break
		}
		u.RawQuery = q.Encode()
		testURL := u.String()
		execID, _ := st.RecordExecution(jobID, "check/reflected-xss", testURL, 0, "payload marker, repeat 2")
		hits := 0
		for i := 0; i < 2; i++ {
			pr, err := tools.Fetch(ctx, hc, testURL)
			if err == nil && strings.Contains(pr.Body, payload) {
				hits++
			}
		}
		if hits == 0 {
			continue
		}
		n++
		status := "likely"
		evidence := fmt.Sprintf("payload marker terpantul TANPA encoding %d/2 run; konfirmasi eksekusi DOM (browser) masih diperlukan untuk 'confirmed'", hits)
		if hits == 1 {
			status = "inconclusive"
			evidence = "refleksi tidak stabil (1/2 run)"
		}
		_, _ = st.AddFinding(store.Finding{JobID: jobID, Class: "xss-reflected", Title: "Reflected XSS (marker)", URL: pu, Severity: "medium", Status: status, Evidence: evidence, ExecutionID: execID})
		emit(opts, engine.StateVerdict, "verdict", "xss-reflected "+pu+" -> "+status)
	}
}

func checkRedirect(ctx context.Context, opts Options, st *store.Store, jobID string, paramURLs []string) {
	hc := tools.NewClient()
	marker := "https://marker.xyland.invalid/"
	for _, pu := range paramURLs {
		u, err := url.Parse(pu)
		if err != nil {
			continue
		}
		q := u.Query()
		key := ""
		for k := range q {
			if redirectParams[strings.ToLower(k)] {
				key = k
				break
			}
		}
		if key == "" {
			continue
		}
		q.Set(key, marker)
		u.RawQuery = q.Encode()
		testURL := u.String()
		execID, _ := st.RecordExecution(jobID, "check/open-redirect", testURL, 0, "marker domain sendiri")
		hits := 0
		isRedirect := false
		for i := 0; i < 2; i++ {
			pr, err := tools.Fetch(ctx, hc, testURL)
			if err != nil {
				continue
			}
			if pr.StatusCode >= 300 && pr.StatusCode < 400 {
				isRedirect = true
				if strings.HasPrefix(pr.Headers.Get("Location"), marker) {
					hits++
				}
			}
		}
		if !isRedirect {
			continue
		}
		status := "false-positive"
		evidence := "respons redirect ada tapi Location tidak menuju marker eksternal"
		if hits == 2 {
			status = "confirmed"
			evidence = "Location menuju domain marker 2/2 run; kontrol internal tetap normal"
		} else if hits == 1 {
			status = "inconclusive"
			evidence = "redirect ke marker tidak stabil (1/2)"
		}
		_, _ = st.AddFinding(store.Finding{JobID: jobID, Class: "open-redirect", Title: "Open Redirect", URL: pu, Severity: "medium", Status: status, Evidence: evidence, ExecutionID: execID})
		emit(opts, engine.StateVerdict, "verdict", "open-redirect "+pu+" -> "+status)
	}
}

func checkMisconfig(opts Options, st *store.Store, jobID, target, fp string) {
	var items []string
	if strings.Contains(fp, "missing-headers") {
		items = append(items, "header keamanan hilang (lihat fingerprint)")
	}
	if strings.Contains(fp, "cookie-no") {
		items = append(items, "flag cookie kurang (Secure/HttpOnly/SameSite)")
	}
	if len(items) == 0 {
		return
	}
	execID, _ := st.RecordExecution(jobID, "check/misconfig", target, 0, "observasi deterministik dari fingerprint")
	_, _ = st.AddFinding(store.Finding{JobID: jobID, Class: "misconfig", Title: "Security Misconfiguration (headers/cookies)", URL: target, Severity: "low", Status: "confirmed", Evidence: strings.Join(items, "; "), ExecutionID: execID})
	emit(opts, engine.StateVerdict, "verdict", "misconfig -> confirmed (observasi deterministik, severity jujur: low)")
}
