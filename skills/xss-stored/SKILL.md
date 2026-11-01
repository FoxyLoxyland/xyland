---
name: xss-stored
description: "Validasi stored XSS pada objek uji milik sendiri, dengan cleanup wajib"
triggers: { fingerprint: ["user-content-storage", "rich-text-or-comment"], phase: validation }
safety_level: 2
context_cost: 2000
validation_rule: knowledge/validation/xss-stored.yaml
---
# Skill: Stored XSS (Level 2 — approval per eksekusi)
## Langkah
1. Buat objek uji dengan akun sendiri berisi payload marker unik non-destruktif.
2. Executor browser membuka halaman tampil objek tsb sebagai pengunjung/aktor lain; TP = marker tereksekusi di DOM, bukan sekadar tersimpan sebagai teks.
3. **Cleanup wajib**: hapus objek uji, catat buktinya di audit log; bila cleanup gagal, eskalasi ke user saat itu juga.
## Jebakan FP
Payload tersimpan tapi selalu di-encode saat tampil; tampil hanya di panel admin diri sendiri tanpa konteks korban (pengaruhi severity, catat apa adanya).
