# 09 — Decisions & Open Questions (ADR Log)

Keputusan di sini mengunci arah coding. Status: `OPEN` = belum diputuskan, `DECIDED` = sudah final & dicatat alasannya.

## D-01 — Nama Project — `DECIDED: xyland`
- Tanggal: 2 Nov 2026 (keputusan user)
- Alasan: nama final dari user; repo GitHub `FoxyLoxyland/xyland`
- Konsekuensi: semua dokumen & binary memakai nama xyland (menggantikan codename sementara sebelumnya)

## D-08 — Workflow Engine — `DECIDED: executor internal subset Osmedeus`
- Tanggal: 2 Nov 2026 (dari research Putaran 2)
- Alasan: tidak ada workflow engine Go yang layak di-embed (Dagu GPL-3.0 + API experimental, Temporal butuh server). Pola Osmedeus (MIT) diadopsi sebagai *desain*: `kind: module` vs `kind: flow`, `depends_on`, `exports`, kondisi, checkpoint SQLite.
- Konsekuensi: kita menulis executor sendiri yang kecil; dilarang menarik dependensi GPL/AGPL ke core.

## D-09 — Lisensi & Batasan Dependensi — `DECIDED: MIT; core hanya dependensi MIT/BSD/Apache`
- Tanggal: 2 Nov 2026
- Alasan: rencana scale-up komersial; research menemukan jebakan AGPL (trufflehog, kiterunner, Arjun) & GPL (gowitness, reNgine, Dagu) — tool tsb hanya boleh jadi referensi pola atau binary eksternal opsional, bukan library core. Secrets scanning memakai pola gitleaks (MIT).
- Konsekuensi: setiap dependensi baru wajib cek lisensi, dicatat di PR.

## D-10 — Arah Agent — `DECIDED: agent-first, engine-guarded`
- Tanggal: 2 Nov 2026 (ralat di docs/11-REVISED-DESIGN.md)
- Alasan: tujuan produk adalah pentest agent yang cepat menemukan vuln, bukan pipeline pasif; guardrail dipindah ke engine deterministic (receipt grounding, verdict, budget, scope, safety gate).

## D-02 — Cara Integrasi ProjectDiscovery Tools — `OPEN`
- Opsi A: sebagai Go library (single binary sejati, tapi dependensi berat & konflik versi mungkin terjadi)
- Opsi B: panggil binary eksternal (user install subfinder/httpx/nuclei terpisah, atau tool kita yang mengelola instalasinya seperti `pdtm`)
- Opsi C: Hybrid — library untuk yang ringan (httpx), binary untuk yang berat (nuclei)
- Menunggu: hasil research arsitektur PD

## D-03 — Niche Fokus Utama v1.0 — `OPEN`
- Opsi ada di `07-NICHE-STRATEGY.md` (#1-#5)
- Draft kecenderungan: bug-bounty workflow umum + validation-first + self-hosted ID/SEA sebagai pintu masuk
- Menunggu: hasil research gap AI pentest Go & API tools

## D-04 — LLM Provider Default — `OPEN`
- Draft: OpenAI-compatible endpoint, default diarahkan ke gateway self-hosted user (9Router di VPS-nya)
- Yang harus diputuskan: model default untuk triage & untuk report, dan batas token per job

## D-05 — Lisensi & Open Source — `OPEN`
- Opsi: MIT / Apache-2.0 untuk core open-source
- Dampak ke model scale-up (premium module terpisah perlu lisensi berbeda)

## D-06 — Storage: SQLite vs JSON — `OPEN (draft: SQLite)`
- Draft di arsitektur: SQLite tanpa CGO
- Alternatif MVP tercepat: JSON flat dulu, migrasi SQLite di v0.5

## D-07 — Target Platform Rilis Pertama — `OPEN (draft: Linux VPS dulu)`
- Konteks: user menjalankan tool di VPS; prioritas Linux amd64
- Windows/macOS menyusul via cross-compile Go

---
### Format Menambah Keputusan
```
## D-XX — Judul — `DECIDED: <pilihan>`
- Tanggal:
- Alasan:
- Konsekuensi:
```
