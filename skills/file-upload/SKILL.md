---
name: file-upload
description: "Uji validasi file upload dengan berkas uji jinak milik sendiri + cleanup"
triggers: { fingerprint: ["file-upload-feature"], phase: validation }
safety_level: 2
context_cost: 2000
validation_rule: knowledge/validation/file-upload.yaml
---
# Skill: File Upload (Level 2 — approval per eksekusi)
## Langkah
1. Petakan aturan yang diklaim server: ekstensi, content-type, ukuran, lokasi penyimpanan & apakah berkas bisa diakses publik.
2. Uji bertahap dengan berkas **jinak**: file teks berisi marker untuk membuktikan jalur simpan/akses; mismatch ekstensi/content-type hanya untuk membuktikan validasi lemah, bukan mengunggah shell.
3. TP untuk kategori berbahaya hanya bila rantai dampak terbukti dengan berkas penanda yang tidak mengeksekusi kode arbitrer di tahap validasi awal; eskalasi = Level 3 manual.
4. Cleanup semua berkas uji & catat di audit log.
## Jebakan FP
Upload "berhasil" tapi berkas tersimpan di luar webroot / di-rename acak tanpa akses; validasi lemah tanpa jalur akses = temuan konfigurasi, bukan RCE.
