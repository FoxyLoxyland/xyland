---
name: sqli-detection
description: "Deteksi SQL injection berbasis error & boolean differential; ekstraksi data BUKAN bagian skill ini"
triggers: { fingerprint: ["db-backed-parameter", "error-reflection"], phase: validation }
safety_level: 1
context_cost: 1900
validation_rule: knowledge/validation/sqli-detection.yaml
---
# Skill: SQL Injection — Deteksi Saja
## Langkah
1. Error-based: picu error DB khas dengan karakter pemutus string; cocokkan signature error per engine (MySQL/PostgreSQL/MSSQL/Oracle) — bukan kata generik "error".
2. Boolean differential: pasangan kondisi benar/salah yang identik struktur; TP butuh selisih isi respons yang stabil (3x konsisten), bukan selisih sekali.
3. Kontrol negatif: nilai acak yang sintaksnya valid tidak boleh menghasilkan selisih apa pun.
## Batasan Keras
- Time-based hanya varian ringan (delay kecil, maks percobaan ketat) dan masuk Level 2.
- **Ekstraksi/dumping data = Level 3 manual-only.** Skill ini berhenti di bukti deteksi.
## Jebakan FP
Halaman error generik aplikasi, WAF yang membalas halaman blokir berisi kata "SQL", respons tidak stabil karena faktor non-DB (load balancer, cache).
