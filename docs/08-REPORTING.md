# 08 — Reporting Spec

## Prinsip
Laporan adalah produk akhir yang dilihat program & triager platform. Tool yang bagus di scan tapi buruk di report akan kalah dari tool yang sebaliknya.

## Output per Run
```
results/<job-id>/
├── summary.md          # ringkasan run: target, jumlah aset, jumlah finding per severity
├── findings.json       # semua finding terstruktur (mesin)
├── assets.json         # semua aset hasil recon/enum
└── reports/
    ├── 001-idor-api-users.md
    ├── 002-xss-reflected-search.md
    └── ...
```

## Struktur Laporan per Finding (mengikuti format HackerOne)
```markdown
# [Title: singkat, spesifik — mis. IDOR on /api/v2/users/{id} allows viewing other users' email]

## Summary
[1-3 kalimat: apa vuln-nya, di mana, dampak singkat]

## Severity
[Critical/High/Medium/Low + alasan singkat / perkiraan CVSS bila relevan]

## Steps to Reproduce
1. [Langkah persis, dengan URL & parameter nyata dari bukti]
2. ...

## Evidence
[Request]
```
...
```
[Response — bagian sensitif diredaksi]
```
...
```

## Proof of Concept
[PoC script terlampir sebagai file terpisah: `poc.py` — standalone, self-verifying.
Ringkasan verdict validasi mesin: status TP/FP/confidence, hasil negative control, reproduksi x/x run.
Detail rule: `validation.yaml`. Aturan lengkap di `10-POC-VALIDATION.md`.
Triager bisa menjalankan ulang PoC tanpa tool kami untuk memverifikasi finding.]

## Impact
[Apa yang bisa dilakukan penyerang dengan ini, berdasarkan bukti — bukan skenario karangan]

## Suggested Remediation
[1-3 saran perbaikan konkret]

---
Generated with xyland — Job <id>, Template <nuclei-template-id>, Status: confirmed/likely
```

## Aturan Penulisan (diterapkan ke AI reporter & template)
- Title harus menyebut jenis vuln + lokasi. Dilarang title generik ("XSS Found").
- Steps to Reproduce harus bisa diikuti triager tanpa menebak — pakai data dari `Evidence`, bukan parafrase AI.
- Impact tidak boleh melebihi bukti. Jika dampak lanjutan hanya kemungkinan, tulis sebagai kemungkinan.
- Data sensitif nyata (token, email orang lain, dsb) yang tertangkap di bukti **wajib diredaksi** di laporan, dengan catatan bahwa data asli tersedia bila diminta program.
- Bahasa laporan: English secara default (standar platform global); opsi ID untuk program lokal.

## Dukungan Platform
| Platform | v0.1 | Catatan |
|---|---|---|
| HackerOne | ✅ Markdown mengikuti struktur di atas | Format paling umum |
| Bugcrowd | ✅ Struktur sama, sesuaikan field severity (VRT) | Tambahkan kategori VRT di v0.5 |
| Program privat / email | ✅ Markdown / plain text | Template email sederhana |
| Intigriti / YesWeHack | Later | Setelah format utama stabil |
