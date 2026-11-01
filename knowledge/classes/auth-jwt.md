# Kelas: Auth & JWT
## Jebakan FP khas
- Token diterima endpoint yang memang publik.
- Klaim token dimodifikasi tanpa membuktikan dampak sesi.
## Checklist negatif
- [ ] alg/kid/jku pada token uji sendiri sudah diuji
- [ ] Token kedaluwarsa & token tanpa tanda tangan ditolak server (uji negatif)
- [ ] Perbedaan respons antar peran terdokumentasi di state model
