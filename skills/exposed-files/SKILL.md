---
name: exposed-files
description: "Pemeriksaan file/endpoint terekspos (.git, .env, backup, debug) dengan baseline anti-200-trap"
triggers: { phase: scanning }
safety_level: 0
context_cost: 1200
validation_rule: knowledge/validation/exposed-files.yaml
---
# Skill: Exposed Files & Misconfig

## Langkah
1. Minta path kandidat dari daftar terkurasi (bukan wordlist raksasa): `.git/config`, `.git/HEAD`, `.env`, file backup umum, endpoint debug/status umum.
2. Untuk tiap path, ambil juga **baseline path ngawur** (`/<acak-tidak-ada>`) di host yang sama.
3. TP hanya bila: isi cocok dengan *format khas* file tsb (mis. `.git/config` punya section `[core]`) DAN baseline tidak menghasilkan isi serupa. Status 200 saja **bukan** bukti (anti-200-trap).

## Jebakan FP Khas
Custom 404 berisi kata kunci; SPA catch-all; halaman WAF; file contoh yang memang sengaja dipublikasikan (`.env.example` tanpa nilai nyata — bila isinya placeholder, verdict FP untuk kategori exposure).

## Artefak Wajib
Cuplikan isi teredaksi, baseline pembanding, `verdict.json` per path.
