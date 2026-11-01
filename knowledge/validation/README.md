# Katalog Validation Rule
Satu file YAML per kelas vuln — pasangan wajib setiap skill (lihat `docs/10-POC-VALIDATION.md` dan format gabungan nuclei+afrog+ekstensi xyland di `docs/11-REVISED-DESIGN.md` §3).
Contoh terisi penuh: `templates/poc/validation-xss-reflected.example.yaml`.
File yang direncanakan (dibangun bertahap sesuai roadmap): `xss-reflected.yaml`, `exposed-files.yaml`, `open-redirect.yaml`, `idor-auth.yaml`, `cors.yaml`, `ssrf-blind.yaml`.
Setiap rule wajib punya: `executor: http|browser`, positive test, negative control, baseline, `repeat: 2`, dan blok `verdict`.
