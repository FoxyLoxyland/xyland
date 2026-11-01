---
name: jwt-analysis
description: "Analisis keamanan JWT sesi uji: alg confusion, kid/jku, klaim & masa berlaku — tanpa menyerang sesi orang lain"
triggers: { fingerprint: ["jwt-session", "bearer-api"], phase: validation }
safety_level: 1
context_cost: 1800
validation_rule: knowledge/validation/jwt.yaml
---
# Skill: JWT Analysis
## Langkah (semua pada token milik sesi uji sendiri)
1. Dekode header/claims: `alg`, `kid`, `jku/x5u`, `exp/iat`, klaim peran. Catat anomali pasif dulu.
2. Tes aktif terbatas pada token uji yang dimodifikasi dari token sendiri: `alg:none`, kebingungan RS256→HS256 memakai kunci publik yang memang tersedia publik, path pada `kid`.
3. TP = server menerima token termodifikasi untuk aksi sesi uji (bukti respons terautentikasi sebagai identitas uji yang ditingkatkan/diubah).
## Jebakan FP
Endpoint publik yang menerima token apa pun karena memang tidak butuh auth; token diterima tapi klaim kritis diabaikan server (tidak ada dampak = bukan finding).
## Batasan
Brute-force secret HS256 skala besar di luar skill ini — hanya daftar kata kecil umum bila ada indikasi kuat, dan itu Level 2. Tidak ada pengujian pada token pengguna nyata.
