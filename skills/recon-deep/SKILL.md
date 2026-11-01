---
name: recon-deep
description: "Recon mendalam: subdomain, DNS, live host, fingerprint, JS & endpoint extraction"
triggers: { phase: recon }
safety_level: 0
context_cost: 2100
---
# Skill: Recon Deep

## Tujuan
Menghasilkan peta aset & fingerprint yang cukup kaya untuk pembentukan hipotesis (doc 11), bukan sekadar daftar host.

## Langkah
1. Subdomain pasif (subfinder) → resolusi DNS (dnsx). Catat wildcard DNS sejak awal (sumber FN/FP klasik).
2. Live probing (httpx): status, title, tech, header keamanan, screenshot `-ss`, hash body (untuk diff & dedup antar run).
3. Crawling (katana `-jc -jsl`): kumpulkan URL, parameter, endpoint API, file JS. Output mentah ke artifact; yang masuk konteks hanya ringkasan terstruktur (P-2).
4. Bangun **fingerprint per aset**: produk+versi (dengan tingkat keyakinan: terverifikasi/banner/tebakan), perilaku auth, jenis endpoint.
5. Bangun awal **state model**: aktor anonim saja dulu; tandai endpoint yang meminta auth.

## Stop Condition
- Kedalaman crawl tercapai atau budget langkah fase habis → catat sebagai coverage note, jangan memaksa.

## Artefak Wajib
`assets.json`, `fingerprint.yaml`, `coverage.md` (apa yang TIDAK terjangkau — bahan coverage gap report).
Setiap baris aset harus punya `execution_id` receipt (doc 11, L-1).
