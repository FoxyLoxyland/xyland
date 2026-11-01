// Package report menyusun laporan Markdown siap submit dari temuan tervalidasi.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/FoxyLoxyland/xyland/internal/store"
)

func Generate(dir, jobID, target string, findings []store.Finding, assets []store.Asset) (string, error) {
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
		fmt.Fprintf(&b, "### [%s] %s\n\n- **Kelas:** %s\n- **URL:** `%s`\n- **Status validasi:** %s\n- **Bukti:** %s\n- **Receipt (execution_id):** %d\n",
			strings.ToUpper(f.Severity), f.Title, f.Class, f.URL, f.Status, f.Evidence, f.ExecutionID)
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
