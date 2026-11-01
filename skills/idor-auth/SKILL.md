---
name: idor-auth
description: "Auth differential antar aktor (anon/A/B) pada state model untuk IDOR & access control"
triggers: { fingerprint: ["authenticated-objects", "numeric-or-uuid-ids"], phase: validation }
safety_level: 1
context_cost: 2400
validation_rule: knowledge/validation/idor-auth.yaml
---
# Skill: IDOR & Access Control (Auth Differential)

## Prasyarat Bukti
State model punya ≥2 aktor uji milik sendiri (user A & user B) dan ≥1 objek milik A yang teridentifikasi.

## Langkah
1. Baseline: A mengakses objek milik A → catat respons ternormalisasi.
2. Differential: B mengakses objek A; anon mengakses objek A. Bandingkan **isi** (bukan status saja): data milik A terbaca B/anon = kandidat TP.
3. Kontrol negatif: B mengakses objek milik B sendiri & objek yang pasti tidak ada — memastikan server memang membedakan kepemilikan, bukan membalas generik untuk semua ID.
4. Bukti dibatasi 1–2 record sampel, teredaksi (SR-04).

## Jebakan FP Khas
Endpoint publik-by-design (profil publik), respons error generik yang terlihat seperti data, ID yang ternyata memang dibagikan (shared link bertoken).

## Stop Condition
Jangan menebak ID massal. Hanya ID yang diketahui dari state model / respons sah yang boleh diuji (tidak ada brute-force enumerasi).

## Artefak Wajib
`validation.yaml`, `poc.py` (memakai 2 sesi uji), `verdict.json`, matriks differential di laporan.
