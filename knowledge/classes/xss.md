# Kelas: XSS
## Jebakan FP khas
- Pantulan ter-encode dengan benar dilaporkan sebagai rentan.
- SPA membalas 200 untuk semua rute (anti-200-trap wajib).
- Payload terpantul di halaman blokir WAF sendiri.
## Checklist negatif (sebelum menyatakan bersih)
- [ ] Konteks HTML, atribut, JS, dan URL sudah diuji terpisah
- [ ] Varian encoding dasar sudah dicoba
- [ ] Konfirmasi browser (bukan curl) untuk kandidat terakhir
