---
name: secrets-in-js
description: "Pemindaian secret terekspos di JS/response publik dengan verifikasi format & konteks (pola gitleaks)"
triggers: { phase: scanning, fingerprint: ["js-files", "public-config"] }
safety_level: 0
context_cost: 1300
---
# Skill: Secrets in JS & Public Responses
## Langkah
1. Pindai berkas JS, HTML, dan respons publik dengan pola per penyedia (format token khas + entropi), mengikuti pendekatan gitleaks (MIT) — bukan regex satu kata "key=".
2. Klasifikasikan: kunci publik-by-design (mis. publishable key, maps key tanpa restriksi server) vs kredensial yang seharusnya rahasia.
3. Bukti nilai penuh **tidak pernah** disalin ke laporan/konteks LLM — simpan hash + 4 karakter terakhir + lokasi (redaksi pra-LLM, doc 11 §6).
## Verifikasi
Validasi aktif terhadap API penyedia (memakai secret untuk membuktikan hidup) adalah Level 2 dan hanya untuk membuktikan validitas minimum (mis. identitas akun), bukan memakai aksesnya.
## Jebakan FP
String contoh di dokumentasi/komentar, kunci demo, token yang sudah di-revoke (tidak bisa dibedakan tanpa validasi — status jujur: `unverified-secret`).
