---
name: cors-check
description: "Validasi CORS misconfiguration secara browser-realistic (bukan curl)"
triggers: { fingerprint: ["api-with-credentials", "origin-reflection"], phase: validation }
safety_level: 1
context_cost: 1600
validation_rule: knowledge/validation/cors.yaml
---
# Skill: CORS Misconfiguration

## Aturan Keras
Kelas ini **tidak boleh** divalidasi dengan curl/httpx saja — tool non-browser mengabaikan same-origin policy dan itulah akar false positive CORS paling terkenal di agent lain (Putaran 3).

## Langkah (executor: browser)
1. Dari origin penyerang (halaman lokal kita), lakukan fetch berkredensial ke endpoint target.
2. TP hanya bila **browser benar-benar memberi akses baca** ke respons (ACAO merefleksikan origin kita DAN `Access-Control-Allow-Credentials: true` DAN data sensitif terbaca di JS).
3. Kontrol negatif: origin acak lain dan request tanpa kredensial — catat perbedaannya.
4. Header ACAO `*` tanpa kredensial pada data publik = **bukan** finding.

## Artefak Wajib
Screenshot/console browser, `poc.py` yang membuka halaman PoC browser, `verdict.json`.
