---
name: ssrf-blind
description: "Deteksi SSRF blind dengan korelasi out-of-band (interactsh) ke server milik sendiri"
triggers: { fingerprint: ["url-parameter", "fetch-or-webhook-feature"], phase: validation }
safety_level: 2
context_cost: 2200
validation_rule: knowledge/validation/ssrf-blind.yaml
---
# Skill: Blind SSRF (Level 2 — approval user per eksekusi)

## Prasyarat Bukti
Fitur target terbukti mengambil URL (fetch/webhook/import/preview). Domain interaksi OOB milik sendiri sudah aktif.

## Langkah
1. Kirim URL berisi token OOB unik per percobaan ke parameter kandidat.
2. Korelasi: interaksi masuk di server OOB dengan token yang sama = sinyal. Kontrol negatif: parameter diisi nilai non-URL — tidak boleh ada interaksi.
3. **Dilarang** mengarahkan target ke alamat internal/cloud metadata pada tahap validasi awal. Eskalasi dampak adalah langkah manual terpisah (Level 3) dengan persetujuan eksplisit.

## Jebakan FP Khas
Prefetcher/CDN pihak ketiga yang mengambil URL atas nama dirinya sendiri; interaksi dari scanner lain pada token yang bocor di log publik (token harus rahasia & unik per run).

## Artefak Wajib
`validation.yaml`, `poc.py`, `verdict.json`, log korelasi OOB (token, waktu, sumber request).
