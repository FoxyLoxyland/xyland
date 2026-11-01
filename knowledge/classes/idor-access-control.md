# Kelas: IDOR & Access Control
## Jebakan FP khas
- Endpoint publik-by-design diklaim IDOR.
- Respons generik untuk semua ID terlihat seperti data orang lain.
## Checklist negatif
- [ ] Matriks anon/A/B/admin-semu sudah lengkap per endpoint objek
- [ ] Method lain (PUT/DELETE versi read-only check) dipertimbangkan
- [ ] Versi API lama ikut dites (api-discovery)
