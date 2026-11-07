package agent

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/store"
	"github.com/FoxyLoxyland/xyland/internal/tools"
)

func fetchPage(ctx context.Context, hc *http.Client, opts Options, page string) (string, bool) {
	var pr *tools.ProbeResult
	var err error
	if opts.AuthA != "" {
		pr, err = tools.FetchWithHeaders(ctx, hc, page, map[string]string{"Cookie": opts.AuthA})
	} else {
		pr, err = tools.Fetch(ctx, hc, page)
	}
	if err != nil || pr.StatusCode != 200 {
		return "", false
	}
	return pr.Body, true
}

func collectForms(ctx context.Context, opts Options, pages []string) []Form {
	hc := tools.NewClient()
	var all []Form
	seen := map[string]bool{}
	for _, pg := range pages {
		if seen[pg] {
			continue
		}
		seen[pg] = true
		body, ok := fetchPage(ctx, hc, opts, pg)
		if !ok {
			continue
		}
		all = append(all, ParseForms(pg, body)...)
	}
	return all
}

// checkCSRF: form POST state-changing tanpa token anti-CSRF
// (knowledge/validation/csrf.yaml). Verdict maksimal "likely" dari bukti pasif:
// ketiadaan token bukan bukti eksploitasi penuh, dan xyland tidak menebak.
func checkCSRF(ctx context.Context, opts Options, st *store.Store, jobID string, pages []string) {
	forms := collectForms(ctx, opts, pages)
	execID, _ := st.RecordExecution(jobID, "check/csrf", opts.Target, 0, "inventaris form POST + cek token anti-CSRF")
	withToken, without := 0, 0
	for _, f := range forms {
		if f.Method != "POST" {
			continue
		}
		if f.HasCSRFToken() {
			withToken++
			continue
		}
		if without >= 3 {
			continue
		}
		without++
		ctxNote := "form dapat dijangkau tanpa sesi uji (halaman publik / sesi tidak disediakan)"
		if opts.AuthA != "" {
			ctxNote = "form dijangkau memakai sesi uji operator (konteks terautentikasi)"
		}
		_, _ = st.AddFinding(store.Finding{JobID: jobID, Class: "csrf",
			Title: "Form POST tanpa token anti-CSRF", URL: f.PageURL, Severity: "medium", Status: "likely",
			Evidence:    "form POST ke " + f.Action + " tidak memuat field token anti-CSRF (csrf/token/authenticity); " + ctxNote + ". Konfirmasi penuh butuh uji submit lintas-origin berizin — verdict ditahan di likely.",
			ExecutionID: execID})
		emit(opts, engine.StateVerdict, "verdict", "csrf "+f.Action+" -> likely (tanpa token)")
	}
	if without > 0 && withToken > 0 {
		emit(opts, engine.StateVerdict, "info", "csrf: aplikasi memakai token di form lain — form tanpa token di atas makin mencurigakan")
	}
}

const uploadMarker = "XYLAND-UPLOAD-MARKER-7F3A"
const uploadName = "xyland-test.svg"

var fileLinkRe = regexp.MustCompile(`(?i)(href|src)\s*=\s*"([^"]*xyland-test\.svg[^"]*)"`)

// checkUpload: unggah file SVG bermarker lewat form upload, lalu buktikan
// file tersimpan & tersaji kembali (knowledge/validation/file-upload.yaml).
func checkUpload(ctx context.Context, opts Options, st *store.Store, jobID string, pages []string) {
	forms := collectForms(ctx, opts, pages)
	var form *Form
	for i := range forms {
		if forms[i].HasFile() && forms[i].Method == "POST" {
			form = &forms[i]
			break
		}
	}
	if form == nil {
		return
	}
	hc := tools.NewClient()
	execID, _ := st.RecordExecution(jobID, "check/file-upload", form.Action, 0, "unggah SVG bermarker + verifikasi tersaji + kontrol negatif")
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><text x="5" y="20">` + uploadMarker + `</text></svg>`
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, in := range form.Inputs {
		if strings.EqualFold(in.Type, "file") {
			fw, err := mw.CreateFormFile(in.Name, uploadName)
			if err != nil {
				return
			}
			_, _ = fw.Write([]byte(svg))
		} else if in.Name != "" {
			_ = mw.WriteField(in.Name, in.Value)
		}
	}
	_ = mw.Close()
	req, err := http.NewRequestWithContext(ctx, "POST", form.Action, &buf)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if opts.AuthA != "" {
		req.Header.Set("Cookie", opts.AuthA)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return
	}
	respBody := readBodyLimit(resp)

	// Kandidat URL penyajian: tautan di respons + tebakan path umum.
	var candidates []string
	push := func(u string) {
		for _, c := range candidates {
			if c == u {
				return
			}
		}
		candidates = append(candidates, u)
	}
	if m := fileLinkRe.FindStringSubmatch(respBody); m != nil {
		if abs, err := resolveAgainst(form.Action, m[2]); err == nil {
			push(abs)
		}
	}
	base, _ := url.Parse(opts.Target)
	for _, pref := range []string{"/uploads/", "/upload/", "/files/", "/media/"} {
		push(base.Scheme + "://" + base.Host + pref + uploadName)
	}
	// kontrol negatif: nama acak pada prefiks pertama yang menebak
	ctrlURL := base.Scheme + "://" + base.Host + "/uploads/xyland-tidak-ada-9z.svg"
	ctrl, _ := tools.Fetch(ctx, hc, ctrlURL)
	ctrlClean := ctrl == nil || (ctrl.StatusCode == 404 && !strings.Contains(ctrl.Body, uploadMarker))

	for _, cand := range candidates {
		hits := 0
		var ct string
		for i := 0; i < 2; i++ {
			pr, err := tools.Fetch(ctx, hc, cand)
			if err == nil && strings.Contains(pr.Body, uploadMarker) {
				hits++
				ct = pr.ContentType
			}
		}
		if hits == 0 {
			continue
		}
		active := strings.Contains(ct, "svg") || strings.Contains(ct, "html")
		if hits == 2 && active && ctrlClean {
			_, _ = st.AddFinding(store.Finding{JobID: jobID, Class: "file-upload",
				Title: "File upload tersimpan & tersaji sebagai konten aktif", URL: form.PageURL, Severity: "high", Status: "confirmed",
				Evidence:    "SVG bermarker diterima form upload dan tersaji utuh 2/2 di " + cand + " dengan Content-Type " + ct + " (konten aktif yang dapat membawa script di origin target); kontrol negatif nama acak bersih",
				ExecutionID: execID})
			emit(opts, engine.StateVerdict, "verdict", "file-upload -> confirmed ("+cand+")")
		} else {
			_, _ = st.AddFinding(store.Finding{JobID: jobID, Class: "file-upload",
				Title: "File upload tersimpan & dapat diakses publik", URL: form.PageURL, Severity: "medium", Status: "likely",
				Evidence:    "file bermarker tersaji kembali di " + cand + " (Content-Type " + ct + ", hits " + itoa(hits) + "/2); penyajian belum terbukti sebagai konten aktif / kontrol belum bersih",
				ExecutionID: execID})
			emit(opts, engine.StateVerdict, "verdict", "file-upload -> likely ("+cand+")")
		}
		return
	}
	emit(opts, engine.StateVerdict, "info", "file-upload: form ditemukan tapi lokasi penyajian tidak terverifikasi (inconclusive — tidak dibuat finding)")
}

func resolveAgainst(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := b.Parse(ref)
	if err != nil {
		return "", err
	}
	return r.String(), nil
}

func readBodyLimit(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b)
}
