package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/store"
	"github.com/FoxyLoxyland/xyland/internal/tools"
)

type nucleiResult struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
}

func parseNucleiJSONL(out string) []nucleiResult {
	var res []nucleiResult
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r nucleiResult
		if json.Unmarshal([]byte(line), &r) == nil && r.TemplateID != "" {
			res = append(res, r)
		}
	}
	return res
}

// runNuclei menjalankan nuclei bila terpasang (spec §4: vulnerability scanning
// dengan template terkurasi — di sini dibatasi severity medium+).
// Hasil nuclei adalah SINYAL scanner: severity critical/high -> likely,
// selain itu inconclusive — verdict final kelas terkait tetap milik rule xyland.
func runNuclei(ctx context.Context, opts Options, st *store.Store, jobID, target string) {
	if !tools.ExternalAvailable("nuclei") {
		return
	}
	out, code, err := tools.RunExternal(ctx, "nuclei", "-silent", "-jsonl", "-severity", "critical,high,medium", "-u", target)
	execID, _ := st.RecordExecution(jobID, "nuclei", target, code, "eksternal via PATH, severity critical,high,medium")
	if err != nil {
		emit(opts, engine.StateExecution, "warn", "nuclei gagal jalan: "+err.Error())
		return
	}
	results := parseNucleiJSONL(out)
	emit(opts, engine.StateExecution, "tool", "nuclei: "+itoa(len(results))+" kandidat")
	seen := map[string]bool{}
	for _, r := range results {
		key := r.TemplateID + "|" + r.MatchedAt
		if seen[key] {
			continue
		}
		seen[key] = true
		status := "inconclusive"
		if r.Info.Severity == "critical" || r.Info.Severity == "high" {
			status = "likely"
		}
		name := r.Info.Name
		if name == "" {
			name = r.TemplateID
		}
		_, _ = st.AddFinding(store.Finding{
			JobID: jobID, Class: "nuclei", Title: name, URL: r.MatchedAt,
			Severity: r.Info.Severity, Status: status,
			Evidence:    "template nuclei " + r.TemplateID + " cocok — sinyal scanner, bukan verdict final xyland",
			ExecutionID: execID,
		})
		emit(opts, engine.StateVerdict, "verdict", "nuclei "+r.TemplateID+" -> "+status)
	}
}
