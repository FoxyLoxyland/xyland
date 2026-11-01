---
name: race-condition
description: "Deteksi race condition pada aksi uji terbatas milik sendiri dengan permintaan paralel terkendali"
triggers: { fingerprint: ["quota-or-balance-action", "one-time-claim"], phase: validation }
safety_level: 2
context_cost: 1900
validation_rule: knowledge/validation/race-condition.yaml
---
# Skill: Race Condition (Level 2 — akun & kuota uji sendiri)
## Langkah
1. Pilih aksi uji yang dibatasi secara bisnis (klaim sekali, kupon uji, batas jumlah) pada akun sendiri.
2. Kirim N permintaan serentak terkendali (gerbang sinkronisasi agar benar-benar bersamaan; N kecil, mis. 10–20) dan bandingkan hasil akhir state dengan batas yang seharusnya.
3. TP = batas terlampaui terbukti dari state akhir (bukan dari status respons semata). Ulangi sekali untuk reproduksi; catat varians.
## Batasan
Dilarang pada aksi finansial nyata / akun orang lain. Beban paralel dibatasi keras dan dihentikan bila target menunjukkan degradasi (SR-08).
## Jebakan FP
Idempotency yang tertunda (state terlihat terlampaui sesaat lalu terkoreksi) — karena itu bukti harus dari state akhir setelah jeda, bukan respons sesaat.
