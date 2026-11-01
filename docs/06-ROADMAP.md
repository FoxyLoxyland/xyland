# 06 — Roadmap

## v0.1 — MVP: "One Domain → One Report" (target 2-4 minggu part-time)
**Tujuan:** membuktikan pipeline end-to-end bekerja, bukan fitur terbanyak.

- [ ] CLI skeleton (cobra): `scan`, `recon`, `report`, `resume`, `config`
- [ ] Config YAML + contoh scope file
- [ ] Integrasi subfinder + httpx + nuclei (pilih satu cara integrasi, konsisten)
- [ ] Storage SQLite + checkpoint per fase (bisa resume)
- [ ] AI triage batch (titik AI #2) + fallback tanpa LLM
- [ ] PoC & Validation v1 (doc 10): katalog rule untuk 3 kelas pertama (exposed files, reflected XSS, open redirect) — tiap finding keluar dengan `validation.yaml` + `poc.py` + verdict TP/FP/inconclusive
- [ ] Report Markdown sederhana per target
- [ ] Audit log & scope enforcement dasar
- [ ] Test end-to-end di target lab / domain milik sendiri

**Definition of Done v0.1:** satu command menghasilkan `summary.md` + laporan per finding untuk 1 domain berizin.

## v0.5 — "Lebih Dalam, Lebih Yakin" (bulan ke-2)
- [ ] Katana crawling + ffuf content discovery
- [ ] AI template selection berdasarkan tech stack (titik AI #1)
- [ ] Katalog rule PoC diperluas: IDOR (auth differential), CORS, SSRF-blind via interactsh, SQLi ringan — termasuk variant matrix & coverage gap report untuk cek false negative
- [ ] Validation fase read-only + bukti request/response rapi, status `confirmed/likely`
- [ ] AI report drafting format HackerOne & Bugcrowd penuh (titik AI #4)
- [ ] TUI progress dengan bubbletea
- [ ] Screenshot bukti via rod (opsional per finding)
- [ ] Proxy support & proxy pool (relevan untuk jalan di VPS)
- [ ] Dataset evaluasi triage AI (20-30 contoh berlabel)

## v1.0 — "Siap Dipakai Orang Lain & Niche Jelas" (bulan ke-3+)
- [ ] MCP server mode — tool bisa dipanggil AI client eksternal
- [ ] Mode scheduled / continuous monitoring di VPS
- [ ] Template nuclei tambahan milik sendiri untuk niche terpilih (lihat 07-NICHE-STRATEGY)
- [ ] Dokumentasi publik, contoh penggunaan, release binary (GitHub Releases, cross-platform)
- [ ] Opsi: dashboard web ringan untuk melihat job & report (baru dipertimbangkan di sini)

## Yang Sengaja TIDAK Dikerjakan Dulu
- Auto-exploit, auto-submit ke platform, brute-force module
- SaaS / multi-user / billing
- Menulis ulang engine scanner sendiri (kita orkestrasi engine yang sudah teruji dulu)
- Mendukung semua jenis target (network, cloud, mobile) — fokus web & API

## Prinsip Roadmap
Setiap versi harus **bisa dipakai hunting beneran** di akhir versinya, bukan demo setengah jadi yang menunggu versi berikutnya.
