package agent

import (
	"context"
	"net/url"
	"strings"

	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/store"
	"github.com/FoxyLoxyland/xyland/internal/tools"
	"github.com/FoxyLoxyland/xyland/internal/validate"
)

// checkIDOR: auth differential (docs/10 §4b & knowledge/validation/idor-auth.yaml).
// Hanya berjalan bila dua sesi uji disediakan (--auth-a/--auth-b).
// Pola: sesi A mengambil objeknya sendiri (baseline kepemilikan);
// sesi B mengambil objek yang sama (uji akses lintas pemilik);
// kontrol: sesi B mengambil id yang tidak ada (harus berbeda).
func checkIDOR(ctx context.Context, opts Options, st *store.Store, jobID string, paramURLs []string) {
	hc := tools.NewClient()
	for _, pu := range paramURLs {
		u, err := url.Parse(pu)
		if err != nil {
			continue
		}
		key := ""
		for k := range u.Query() {
			if idParams[strings.ToLower(k)] {
				key = k
				break
			}
		}
		if key == "" {
			continue
		}
		execID, _ := st.RecordExecution(jobID, "check/idor-auth", pu, 0, "auth differential A vs B + kontrol id tak dikenal")
		own, errA := tools.FetchWithHeaders(ctx, hc, pu, map[string]string{"Cookie": opts.AuthA})
		cross, errB := tools.FetchWithHeaders(ctx, hc, pu, map[string]string{"Cookie": opts.AuthB})
		if errA != nil || errB != nil || own.StatusCode != 200 || cross.StatusCode != 200 {
			continue
		}
		ctrlURL, _, _ := withFirstParam(pu, "999999999", func(k string) bool { return strings.EqualFold(k, key) })
		ctrl, _ := tools.FetchWithHeaders(ctx, hc, ctrlURL, map[string]string{"Cookie": opts.AuthB})
		simCross := validate.Similarity(own.Body, cross.Body)
		if simCross < 0.85 || len(own.Body) < 50 {
			continue // sesi B tidak mendapat isi yang sama — bukan indikasi IDOR
		}
		status := "likely"
		evidence := "sesi B menerima respons nyaris identik dengan objek milik sesi A (similarity " + f2(simCross) + "), tapi kontrol tidak bersih"
		if ctrl != nil && validate.Similarity(own.Body, ctrl.Body) < 0.5 {
			status = "confirmed"
			evidence = "sesi B membaca objek milik sesi A (similarity " + f2(simCross) + "); kontrol id tak dikenal jelas berbeda — kontrol akses objek tidak ditegakkan"
		}
		_, _ = st.AddFinding(store.Finding{JobID: jobID, Class: "idor", Title: "IDOR / Broken Access Control", URL: pu, Severity: "high", Status: status, Evidence: evidence, ExecutionID: execID})
		emit(opts, engine.StateVerdict, "verdict", "idor "+pu+" -> "+status)
	}
}

func f2(x float64) string {
	// format dua desimal tanpa fmt untuk helper kecil ini
	whole := int(x)
	frac := int((x - float64(whole)) * 100)
	s := itoa(whole) + "."
	if frac < 10 {
		s += "0"
	}
	return s + itoa(frac)
}
