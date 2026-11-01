---
name: subdomain-takeover
description: "Deteksi kandidat subdomain takeover dari CNAME menggantung ke layanan pihak ketiga"
triggers: { phase: enumeration, fingerprint: ["dangling-cname"] }
safety_level: 0
context_cost: 900
---
# Skill: Subdomain Takeover — Deteksi Saja
## Langkah
1. Dari hasil enum, kumpulkan CNAME yang menunjuk ke layanan pihak ketiga (hosting, SaaS, storage, dsb).
2. Kandidat = target layanan merespons dengan tanda khas "belum diklaim / tidak ditemukan" untuk nama itu.
3. Verifikasi silang: pola respons harus cocok dengan fingerprint layanan yang dikenal DAN nama target di layanan itu terbukti belum terdaftar (cek read-only).
## Batasan Keras
Skill ini **tidak melakukan klaim/pendaftaran** sumber daya apa pun atas nama siapa pun. Klaim nyata untuk membuktikan takeover adalah tindakan terpisah di luar tool, dengan persetujuan & tanggung jawab user, dan banyak program melarangnya — status finding maksimal `likely` dari deteksi.
## Jebakan FP
Layanan yang membalas pesan generik untuk semua nama; CNAME ke layanan internal perusahaan yang memang disengaja.
