# Kelas: SQL Injection
## Jebakan FP khas
- Selisih respons karena cache/load balancer, bukan kondisi boolean.
- Kata 'SQL' di halaman blokir WAF.
## Checklist negatif
- [ ] Pasangan boolean diulang 3x dan stabil
- [ ] Parameter di body & header (bukan hanya query) dipertimbangkan
- [ ] Deteksi berhenti di bukti — ekstraksi manual-only
