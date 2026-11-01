---
name: business-logic
description: "Pengujian business logic di atas state model: urutan langkah, lompatan state, manipulasi nilai & peran"
triggers: { fingerprint: ["multi-step-flow", "pricing-or-quota", "role-based-features"], phase: validation }
safety_level: 2
context_cost: 2300
---
# Skill: Business Logic (berbasis State Model, doc 11 §5)
## Langkah
1. Dari state model, gambar transisi yang sah untuk satu alur bisnis (mis. buat → bayar → terima; atau daftar → verifikasi → aktif).
2. Uji penyimpangan satu per satu pada **objek uji sendiri**: melompati langkah, mengulang langkah yang harusnya sekali, nilai negatif/nol pada parameter bisnis, memakai fitur peran lebih tinggi dengan sesi peran rendah.
3. TP hanya bila state akhir melanggar aturan bisnis yang bisa ditunjukkan (bukti: state sebelum vs sesudah + aturan yang dilanggar), bukan "responsnya 200".
## Catatan Kejujuran
Kelas ini paling tidak bisa diotomatisasi penuh — skill ini memberi struktur & checklist, dan verdict `likely` dari agent wajib review manusia sebelum laporan. Mencatat keterbatasan ini adalah fitur, bukan kelemahan.
## Jebakan FP
Perilaku yang terlihat aneh tapi memang kebijakan bisnis yang disengaja (promo, grace period) — bila ragu, status `needs-manual-check`.
