---
name: subdomain-enum
description: "Enumerasi subdomain pasif+aktif dan resolusi DNS"
triggers: { phase: recon, needs: root-domain }
safety_level: 0
context_cost: 900
---
# Skill: Subdomain Enumeration
Pasif dulu (subfinder dari sumber publik), lalu resolusi (dnsx). Deteksi wildcard: resolve 2 nama acak yang pasti tidak ada; bila keduanya menjawab IP yang sama, tandai domain sebagai wildcard dan saring hasil aktif terhadap pola itu. Simpan sumber tiap subdomain (untuk dedup & audit). Brute-force aktif hanya dalam mode `deep` dan dengan wordlist kecil terkurasi.
