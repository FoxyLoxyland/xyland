---
name: xss-reflected
description: "Tes & validasi reflected XSS dengan payload marker non-destruktif"
triggers: { fingerprint: ["param-reflection", "content-type:text/html"], phase: validation }
safety_level: 1
context_cost: 1800
validation_rule: knowledge/validation/xss-reflected.yaml
---
# Skill: Reflected XSS

## Prasyarat Bukti
Parameter terbukti terpantul di respons (dari recon/scan), content-type HTML.

## Langkah
1. Jalankan validation rule pasangan (positive + negative control + baseline, reproduksi 2x).
2. Karena kelas ini milik browser, konfirmasi akhir **wajib executor browser** (doc 11, L-3): payload marker ter-eksekusi di DOM, bukan sekadar terpantul di teks.
3. Bila baseline ≈ respons payload (SPA catch-all) → verdict maksimal `inconclusive` (anti-200-trap, L-2).

## Jebakan FP Khas
Pantulan yang sudah di-encode dengan benar; pantulan di konteks JSON/atribut yang tidak bisa keluar; WAF yang memantulkan payload di halaman blokirnya sendiri.

## Artefak Wajib
`validation.yaml` terisi, `poc.py`, `verdict.json`, screenshot/DOM snapshot browser sebagai bukti.
