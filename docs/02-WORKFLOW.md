# 02 — Workflow End-to-End

_Prinsip: setiap fase punya Input → Process (Tool Go) → Peran AI → Output yang terstruktur & bisa dipakai fase berikutnya tanpa parsing ulang file teks mentah._

```
[0 Scope] → [1 Recon] → [2 Enum] → [3 Scan] → [4 AI Triage] → [5 Validation] → [6 Dedup] → [7 Report]
```

## Fase 0 — Scope & Target Management
- **Input:** domain/list, file scope, program rules (HackerOne/Bugcrowd URL bila ada)
- **Process:** normalisasi target, load in-scope/out-of-scope, buat `job` baru di storage
- **Peran AI:** (opsional) bantu parse aturan program dari teks menjadi daftar scope terstruktur — hasil wajib dikonfirmasi user
- **Output:** `job.json` berisi target terverifikasi & batasan rate-limit
- **Guardrail:** fase aktif berikutnya menolak host di luar scope

## Fase 1 — Recon (Passive → Active)
- **Input:** domain root
- **Tools Go:** subfinder (passive subdomain), dnsx (DNS resolution), gau/waybackurls (URL historis — v0.5)
- **Peran AI:** tidak ada di fase ini selain ringkasan jumlah aset. Jaga biaya.
- **Output:** daftar subdomain + IP + DNS record → `assets` table

## Fase 2 — Enumeration & Fingerprinting
- **Input:** daftar subdomain
- **Tools Go:** httpx (live check, status, title, tech), naabu (port — mode konservatif, v0.5), katana (crawl — v0.5)
- **Peran AI:** clustering aset (mis. kelompokkan staging/admin/API), tandai aset menarik (`interesting_assets`)
- **Output:** daftar live host dengan tech stack, status code, kategori

## Fase 3 — Vulnerability Scanning
- **Input:** live hosts + URL hasil crawl
- **Tools Go:** nuclei (template terkurasi per kategori: exposures, misconfig, cves, api), dalfox (XSS — v0.5), ffuf (content discovery — v0.5)
- **Peran AI:** memilih set template berdasarkan tech stack hasil Fase 2 (mis. WordPress → template WP saja), bukan menjalankan semua template membabi buta
- **Output:** raw findings (JSON) dengan template ID, severity mentah, bukti request/response

## Fase 4 — AI Triage
- **Input:** raw findings (batch, mis. 20-50 per panggilan LLM)
- **Process:** AI memberi skor prioritas (impact × likelihood × uniqueness), kategori ulang, penjelasan singkat
- **Peran AI:** **inti fase ini** — tapi AI tidak boleh menambah finding baru
- **Output:** findings teranking dengan label `priority: high/medium/low`, `confidence: 0-100`
- **Guardrail:** jika LLM gagal/offline, workflow tetap jalan dengan ranking berbasis severity nuclei saja

## Fase 5 — Validation & PoC Aman (detail: `10-POC-VALIDATION.md`)
- **Input:** finding prioritas high/medium
- **Process:** untuk tiap finding, engine mengambil rule dari katalog per kelas vuln dan menghasilkan 2 artefak: `validation.yaml` (positive test + negative control + baseline + syarat reproduksi) dan `poc.py` standalone yang self-verifying. Rule dijalankan mesin: positive vs kontrol negatif vs baseline, diulang 2x.
- **Verdict (deterministic, bukan opini AI):** `confirmed` (TP) / `likely` / `false-positive` / `inconclusive`. Hanya `confirmed`/`likely` yang lanjut ke Reporting.
- **False Negative check (jalur terpisah):** variant matrix (encoding/case/method/header), auth differential (tanpa auth vs user A vs user B), dan coverage gap report — endpoint yang ditemukan tapi tidak pernah dites. Kandidat baru dari jalur ini wajib masuk kembali ke validasi yang sama sebelum bisa jadi finding.
- **Peran AI:** memilih rule katalog, mengisi parameter dari bukti, menjelaskan verdict. AI tidak mengubah verdict dan tidak menulis payload di luar katalog untuk eksekusi otomatis.
- **Guardrail — Human-in-the-loop & Safety Rules SR-01..SR-10:** default read-only (Level 0–1). Level 2 (intrusif) wajib approval user per eksekusi. Level 3 (SQLi extraction, RCE, dll) manual-only: tool hanya memberi instruksi + script untuk dibaca, tidak mengeksekusi.
- **Output:** per finding: `validation.yaml`, `poc.py`, `verdict.json`, bukti bersih di `evidence/`

## Fase 6 — Deduplication & Chaining
- **Input:** validated findings
- **Process:** dedup berdasarkan (host + template + parameter), gabungkan bukti; AI mengusulkan chain antar finding (info disclosure → IDOR, dsb) sebagai *saran*, bukan klaim otomatis
- **Output:** daftar final unik siap lapor

## Fase 7 — Reporting
- **Input:** final findings
- **Process:** generate laporan per finding dari template platform (lihat 08-REPORTING.md)
- **Peran AI:** menulis draft: title, summary, steps to reproduce, impact, remediation — dari bukti nyata, bukan karangan
- **Output:** `report.md` per finding + `summary.md` per target/run
- **Guardrail:** user selalu review & edit sebelum submit; tool tidak auto-submit ke platform di v0.1

## Mode Jalan
| Mode | Fase | Keterangan |
|---|---|---|
| `passive` | 0-1 | Tanpa menyentuh target secara aktif |
| `standard` (default) | 0-4, 6-7 | Scan aktif aman + triage |
| `deep` | 0-7 semua | Termasuk crawling, fuzzing, validasi — butuh konfirmasi |

## Resume & State
Setiap fase menulis checkpoint. Jika proses mati di Fase 3, `xyland resume <job-id>` melanjutkan dari Fase 3 tanpa mengulang recon.
