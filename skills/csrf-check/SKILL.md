---
name: csrf-check
description: "Validasi CSRF pada aksi uji milik sendiri: token, SameSite, dan dampak state yang teramati"
triggers: { fingerprint: ["cookie-auth", "state-changing-form"], phase: validation }
safety_level: 2
context_cost: 1700
validation_rule: knowledge/validation/csrf.yaml
---
# Skill: CSRF (Level 2 — hanya aksi uji akun sendiri)
## Langkah
1. Inventarisasi aksi pengubah state pada akun uji: apakah ada token anti-CSRF, bagaimana atribut SameSite cookie sesi, apakah server memvalidasi Origin/Referer.
2. PoC browser lintas-origin (halaman kita → target) terhadap aksi **berdampak rendah & bisa dibalikkan** pada akun sendiri (mis. ubah nama tampilan uji).
3. TP = state benar-benar berubah terbukti dari sesi korban uji, bukan sekadar request terkirim.
## Jebakan FP
Klaim CSRF pada aksi yang hasilnya tidak terverifikasi; aksi yang sebenarnya butuh re-auth; SameSite=Lax yang justru memblokir POST lintas situs (uji per method).
## Batasan
Dilarang menargetkan aksi destruktif/ireversibel (hapus akun, transfer, ganti email/password) — itu Level 3, cukup dibuktikan dari analisis token/SameSite tanpa eksekusi.
