package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/store"
	"github.com/FoxyLoxyland/xyland/internal/tools"
)

var ssrfParams = map[string]bool{
	"url": true, "uri": true, "link": true, "callback": true, "webhook": true,
	"fetch": true, "image": true, "img": true, "src": true, "endpoint": true,
	"proxy": true, "load": true, "resource": true, "file_url": true, "image_url": true,
}

// oobServer adalah callback listener lokal untuk membuktikan SSRF blind:
// bila server target benar-benar melakukan request ke URL unik kita,
// itu bukti kausal (sesuai knowledge/validation/ssrf-blind.yaml).
type oobServer struct {
	srv  *http.Server
	ln   net.Listener
	mu   sync.Mutex
	hits map[string]int
	base string
}

func startOOB() (*oobServer, error) {
	o := &oobServer{hits: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.hits[strings.Trim(r.URL.Path, "/")]++
		o.mu.Unlock()
		w.WriteHeader(200)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	o.ln = ln
	o.srv = &http.Server{Handler: mux}
	// Base bisa ditimpa env (mis. URL interactsh / host publik operator)
	if v := os.Getenv("XYLAND_OOB_BASE"); v != "" {
		o.base = strings.TrimRight(v, "/")
	} else {
		o.base = "http://" + ln.Addr().String()
	}
	go o.srv.Serve(ln)
	return o, nil
}

func (o *oobServer) hit(token string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.hits[token]
}

func (o *oobServer) close() { _ = o.srv.Close() }

func randToken() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "xy" + hex.EncodeToString(b)
}

// checkSSRFBlind: parameter mirip URL diisi alamat callback unik kita.
func checkSSRFBlind(ctx context.Context, opts Options, st *store.Store, jobID string, paramURLs []string) {
	var candidates []string
	for _, pu := range paramURLs {
		u, err := url.Parse(pu)
		if err != nil {
			continue
		}
		for k, vs := range u.Query() {
			if ssrfParams[strings.ToLower(k)] || (len(vs) > 0 && strings.HasPrefix(vs[0], "http")) {
				candidates = append(candidates, pu)
				break
			}
		}
	}
	if len(candidates) == 0 {
		return
	}
	oob, err := startOOB()
	if err != nil {
		emit(opts, engine.StateExecution, "warn", "OOB listener gagal: "+err.Error())
		return
	}
	defer oob.close()
	hc := tools.NewClient()
	n := 0
	for _, pu := range candidates {
		if n >= 3 {
			break
		}
		token := randToken()
		testURL, _, ok := withFirstParam(pu, oob.base+"/"+token, func(k string) bool {
			return ssrfParams[strings.ToLower(k)]
		})
		if !ok {
			// parameter terdeteksi dari nilai URL, bukan nama — ganti parameter pertama
			testURL, _, ok = withFirstParam(pu, oob.base+"/"+token, nil)
			if !ok {
				continue
			}
		}
		execID, _ := st.RecordExecution(jobID, "check/ssrf-blind", testURL, 0, "callback OOB token unik")
		_, _ = tools.Fetch(ctx, hc, testURL)
		// beri waktu request server-side tiba
		hit := 0
		for i := 0; i < 12; i++ {
			if hit = oob.hit(token); hit > 0 {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if hit == 0 {
			continue
		}
		n++
		evidence := fmt.Sprintf("callback OOB diterima %d kali untuk token unik %s — server target benar-benar melakukan request ke URL yang dikendalikan penguji (bukti kausal blind SSRF). Listener: %s", hit, token, oob.base)
		_, _ = st.AddFinding(store.Finding{JobID: jobID, Class: "ssrf-blind", Title: "Server-Side Request Forgery (blind, OOB)", URL: pu, Severity: "high", Status: "confirmed", Evidence: evidence, ExecutionID: execID})
		emit(opts, engine.StateVerdict, "verdict", "ssrf-blind "+pu+" -> confirmed (OOB)")
	}
}
