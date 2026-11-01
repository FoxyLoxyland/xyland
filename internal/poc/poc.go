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
	}
	return "", false
}

var _ = strings.TrimSpace
