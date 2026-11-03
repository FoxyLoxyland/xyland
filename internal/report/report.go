// Package report menyusun laporan Markdown siap submit dari temuan tervalidasi.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/FoxyLoxyland/xyland/internal/store"
)

func Generate(dir, jobID, target string, findings []store.Finding, assets []store.Asset, covs ...Coverage) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# Xyland Scan Report\n\n- **Job:** `%s`\n- **Target:** %s\n- **Aset hidup:** %d\n- **Finding tervalidasi (confirmed/likely):** %d\n\n",
		jobID, target, len(assets), countReportable(findings))
	b.WriteString("## Assets\n\n")
	for _, a := range assets {
		fmt.Fprintf(&b, "- `%s` — %d — %s\n", a.URL, a.StatusCode, a.Title)
	}
	b.WriteString("\n## Findings\n\n")
	for _, f := range findings {
		if f.Status != "confirmed" && f.Status != "likely" {
			continue
		}
		fmt.Fprintf(&b, "### [%s] %s\n\n- **Kelas:** %s\n- **URL:** `%s`\n- **Status validasi:** %s\n- **Prioritas triage:** %.1f\n- **Bukti:** %s\n- **Receipt (execution_id):** %d\n",
			strings.ToUpper(f.Severity), f.Title, f.Class, f.URL, f.Status, Priority(f), f.Evidence, f.ExecutionID)
		if f.PocPath != "" {
			fmt.Fprintf(&b, "- **PoC:** `%s` (self-verifying, jalankan untuk reproduksi)\n", filepath.Base(f.PocPath))
		}
		b.WriteString("\n")
	}
	b.WriteString("## Catatan Validasi\n\n")
	for _, f := range findings {
		if f.Status == "confirmed" || f.Status == "likely" {
			continue
		}
		fmt.Fprintf(&b, "- `%s` %s — %s: %s\n", f.Class, f.URL, f.Status, f.Evidence)
	}
	if len(covs) > 0 {
		cov := covs[0]
		fmt.Fprintf(&b, "\n## Coverage Gap (potensi false negative)\n\n- URL berparameter ditemukan: %d\n- Teruji (muncul sebagai subjek check): %d\n", len(cov.Discovered), len(cov.Tested))
		for _, u := range cov.Untested {
			fmt.Fprintf(&b, "- BELUM TERUJI: `%s`\n", u)
		}
		b.WriteString("\n")
	}
	if chains := Chains(findings); len(chains) > 0 {
		b.WriteString("\n## Kemungkinan Chaining (saran analisis — bukan finding)\n\n")
		for _, c := range chains {
			b.WriteString("- " + c + "\n")
		}
	}
	b.WriteString("\n---\nDihasilkan xyland — hanya finding confirmed/likely yang masuk bagian Findings (prinsip: no exploit, no report).\n")

	path := filepath.Join(dir, "report.md")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func countReportable(fs []store.Finding) int {
	n := 0
	for _, f := range fs {
		if f.Status == "confirmed" || f.Status == "likely" {
			n++
		}
	}
	return n
}

// Coverage adalah ringkasan coverage-gap (FR-14).
type Coverage struct {
	Discovered []string
	Tested     []string
	Untested   []string
}

// statusRank: confirmed paling kuat.
func statusRank(s string) int {
	switch s {
	case "confirmed":
		return 4
	case "likely":
		return 3
	case "inconclusive":
		return 2
	case "false-positive":
		return 1
	}
	return 0
}

func severityWeight(s string) float64 {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	}
	return 1
}

func statusWeight(s string) float64 {
	switch s {
	case "confirmed":
		return 1
	case "likely":
		return 0.7
	case "inconclusive":
		return 0.3
	}
	return 0
}

// Priority adalah skor triage deterministik (FR-04): severity x kekuatan verdict.
func Priority(f store.Finding) float64 {
	return severityWeight(f.Severity) * statusWeight(f.Status)
}

// Dedup menggabungkan finding duplikat (kelas + URL ternormalisasi),
// mempertahankan status terkuat. Daftar mentah di ledger tidak diubah (audit).
func Dedup(in []store.Finding) []store.Finding {
	seen := map[string]int{}
	var out []store.Finding
	for _, f := range in {
		key := f.Class + "|" + strings.TrimRight(f.URL, "/")
		if i, ok := seen[key]; ok {
			if statusRank(f.Status) > statusRank(out[i].Status) {
				out[i] = f
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, f)
	}
	// urut prioritas triage menurun (bubble sort sederhana, daftar kecil)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if Priority(out[j]) > Priority(out[i]) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// GenerateJSON menulis report.json (spec §4: output JSON + Markdown).
func GenerateJSON(dir, jobID, target string, findings []store.Finding, assets []store.Asset) (string, error) {
	type jFinding struct {
		Class    string  `json:"class"`
		Title    string  `json:"title"`
		URL      string  `json:"url"`
		Severity string  `json:"severity"`
		Status   string  `json:"status"`
		Priority float64 `json:"priority"`
		Evidence string  `json:"evidence"`
		Poc      string  `json:"poc,omitempty"`
		Receipt  int64   `json:"execution_id"`
	}
	type jAsset struct {
		URL    string `json:"url"`
		Status int    `json:"status_code"`
		Title  string `json:"title"`
	}
	doc := map[string]any{"job": jobID, "target": target}
	var ja []jAsset
	for _, a := range assets {
		ja = append(ja, jAsset{a.URL, a.StatusCode, a.Title})
	}
	doc["assets"] = ja
	var jf []jFinding
	for _, f := range findings {
		jf = append(jf, jFinding{f.Class, f.Title, f.URL, f.Severity, f.Status, Priority(f), f.Evidence, filepath.Base(f.PocPath), f.ExecutionID})
	}
	doc["findings"] = jf
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// Chains menyusun saran attack chaining DETERMINISTIK dari kombinasi finding
// (spec §4 Later). Ini SARAN analisis, bukan finding — tidak masuk verdict.
func Chains(findings []store.Finding) []string {
	has := map[string]bool{}
	var misconfigEvidence string
	for _, f := range findings {
		if f.Status == "confirmed" || f.Status == "likely" {
			has[f.Class] = true
			if f.Class == "misconfig" {
				misconfigEvidence += f.Evidence + ";"
			}
		}
	}
	var out []string
	if has["exposure"] {
		out = append(out, "Exposure (file sensitif) -> unduh materi yang bocor untuk audit white-box: cari secret, kredensial, dan endpoint internal sebagai bahan hipotesis lanjutan.")
	}
	if has["xss-reflected"] && strings.Contains(misconfigEvidence, "cookie-no-httponly") {
		out = append(out, "Reflected XSS + cookie tanpa HttpOnly -> rantai pencurian sesi layak diuji (dampak XSS naik dari sekadar refleksi menjadi account takeover).")
	}
	if has["sqli"] {
		out = append(out, "SQLi terkonfirmasi -> eskalasi ekstraksi data adalah Level 3 (manual-only, wajib approval eksplisit); mode deteksi default xyland berhenti di sini.")
	}
	if has["idor"] && has["cors"] {
		out = append(out, "IDOR + CORS berkredensial -> data objek lintas-pemilik berpotensi juga terbaca lintas-origin; prioritaskan perbaikan kontrol akses di server.")
	}
	if has["open-redirect"] {
		out = append(out, "Open Redirect -> periksa apakah aplikasi punya alur OAuth/SSO: redirect terbuka dapat dirangkai untuk token theft & phishing yang meyakinkan.")
	}
	if has["ssrf-blind"] {
		out = append(out, "SSRF -> rantai klasik berikutnya adalah metadata cloud (169.254.169.254) dan layanan internal; uji hanya dalam scope & level yang disetujui.")
	}
	return out
}
