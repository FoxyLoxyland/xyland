# 01 — Product Spec v0.1

_Terakhir update: 1 Nov 2026 — Draft, menunggu hasil research repo & keputusan di 09-DECISIONS.md_

## 1. Problem
Bug bounty hunter menghabiskan sebagian besar waktu bukan di eksploitasi, tapi di:
- Chaining banyak tool manual (subfinder → httpx → nuclei → katana → ffuf → ...)
- Menyaring ratusan hasil scan yang mayoritas false positive / duplicate / low-value
- Menulis ulang temuan menjadi laporan yang rapi untuk platform

Akibatnya: lambat, tidak konsisten antar target, dan banyak finding bagus terlewat karena kelelahan triage.

## 2. Target User
| Segmen | Deskripsi | Prioritas |
|---|---|---|
| Primary | Bug bounty hunter solo / part-time, nyaman di CLI, target web & API | v0.1 |
| Secondary | Pentester / red team kecil yang butuh recon+scan otomatis untuk engagement berizin | v0.5 |
| Later | Tim security / SaaS user yang butuh scheduled scanning | v1.0+ |

**Bukan target awal:** enterprise GRC, network pentest skala besar, mobile pentest.

## 3. Value Proposition
> "Dari satu domain, satu command, sampai draft laporan yang tervalidasi — dalam satu binary Go."

Pembeda vs tools existing (hipotesis, divalidasi research):
- Native Go = single binary, cepat, concurrency bagus untuk scanning.
- AI hanya di titik yang bernilai: planning, triage, chaining insight, validasi, dan penulisan laporan.
- Workflow bug-bounty-specific (scope, dedup, severity platform, format laporan), bukan pentest generik.

## 4. Scope

### In Scope — v0.1 (MVP)
- [ ] Input target: single domain / list domain, file scope (in-scope & out-of-scope)
- [ ] Recon subdomain (wrapper/integrasi subfinder)
- [ ] Live host probing (httpx) + tech fingerprint
- [ ] Vulnerability scanning (nuclei dengan template terkurasi)
- [ ] AI triage: ranking severity, dedup, penjelasan kenapa finding penting
- [ ] Output: JSON + Markdown report per target
- [ ] Konfigurasi via YAML + env untuk LLM provider (OpenAI-compatible API — termasuk gateway self-hosted seperti 9Router)
- [ ] Scope enforcement: tool menolak scan host di luar scope yang didefinisikan user

### Out of Scope — v0.1 (sengaja TIDAK dibuat dulu)
- Eksploitasi otomatis agresif / auto-exploit tanpa konfirmasi manusia
- Brute-force / credential attacks
- GUI / web dashboard (CLI + TUI sederhana dulu)
- Multi-user, billing, SaaS tenancy
- Network / AD / cloud pentest module
- Mobile app pentest

### In Scope — PoC & Validation (fitur inti, ditambahkan 1 Nov 2026)
Detail penuh di `docs/10-POC-VALIDATION.md`:
- Setiap finding dilengkapi **Validation Rule** (`validation.yaml`): positive test + negative control + baseline + syarat reproduksi
- Setiap finding dilengkapi **PoC Script** standalone (`poc.py` default, opsi `poc.sh`/`poc.go`) yang self-verifying: mencetak verdict & exit code standar
- **Verdict Engine** mengklasifikasikan tiap finding: `confirmed` (TP) / `likely` / `false-positive` / `inconclusive` — berdasarkan bukti rule, bukan opini AI
- **False Negative check**: variant matrix, auth differential, dan coverage gap report (endpoint yang ditemukan tapi tidak pernah dites)
- Safety Rules SR-01 s/d SR-10: scope-only, read-only default, tanpa payload destruktif, bukti sampel terbatas, Level 2 wajib approval user, Level 3 manual-only

### In Scope — Later (v0.5 / v1.0, lihat Roadmap)
- Crawling (katana) + directory/API fuzzing (ffuf)
- Screenshot / bukti request-response untuk PoC tervalidasi
- Attack chaining suggestion (mis. SSRF → internal metadata)
- MCP server mode: tool bisa dipanggil dari Claude / AI client lain
- Scheduled / continuous monitoring mode di VPS

## 5. Functional Requirements
| ID | Requirement | Prioritas |
|---|---|---|
| FR-01 | User bisa menjalankan full workflow dengan 1 command: `xyland scan -t target.com` | Must |
| FR-02 | Setiap fase bisa dijalankan terpisah: `xyland recon`, `xyland scan`, `xyland report` | Must |
| FR-03 | Hasil setiap fase disimpan terstruktur (JSON/SQLite) dan bisa di-resume jika proses terputus | Must |
| FR-04 | AI triage menghasilkan: skor prioritas, kategori, ringkasan dampak, dan saran langkah validasi | Must |
| FR-05 | Setiap finding menyimpan bukti: URL, template ID, request/response (dipotong & diredaksi), timestamp | Must |
| FR-06 | Report generator menghasilkan draft format HackerOne & Bugcrowd (Markdown) | Must |
| FR-07 | User bisa memilih LLM provider/model via config tanpa recompile | Must |
| FR-08 | Semua aksi aktif (scan/validasi) tercatat di audit log lokal | Must |
| FR-09 | Mode `--dry-run` / `--passive-only` untuk recon tanpa menyentuh target secara aktif | Should |
| FR-10 | Plugin/template system: user bisa menambah nuclei template & wordlist sendiri | Should |
| FR-11 | Setiap finding punya `validation.yaml` (positive test + negative control + baseline + reproducibility) dari katalog rule per kelas vuln | Must |
| FR-12 | Setiap finding punya PoC script standalone yang self-verifying (verdict + exit code 0/2/3/4) dan aman by construction sesuai Safety Rules di doc 10 | Must |
| FR-13 | Verdict Engine memberi label TP/FP/inconclusive berbasis eksekusi rule, dan hanya `confirmed`/`likely` yang boleh masuk laporan final | Must |
| FR-14 | Setiap run menghasilkan coverage gap report + hasil variant/auth-differential check sebagai daftar potensi false negative | Should |

## 6. Non-Functional Requirements
- **Performa:** manfaatkan goroutine worker pool; rate-limit bisa diatur per target (`-rate-limit`, `-concurrency`).
- **Portabilitas:** single binary untuk Linux (VPS) & lokal; target utama Linux amd64/arm64.
- **Keamanan penggunaan:** scope check sebelum setiap fase aktif, rate-limit default konservatif, tidak menyimpan API key di file hasil scan.
- **Biaya AI terkendali:** AI hanya dipanggil pada tahap triage/validasi/report, bukan per-request scan. Ada estimasi & limit token per run.
- **Observability:** log terstruktur, progress per fase terlihat di terminal (TUI/spinner).
- **Extensibility:** penambahan tool baru cukup implementasi interface `Tool` standar (lihat Architecture).

## 7. Success Criteria MVP
- Bisa menjalankan end-to-end pada 1 target lab / target berizin dalam < 15 menit.
- AI triage mengurangi daftar mentah nuclei menjadi daftar prioritas yang masuk akal (dedup bekerja).
- Draft laporan yang dihasilkan bisa di-copy ke HackerOne dengan edit minimal.
- Binary bisa di-build & jalan di VPS user tanpa dependensi Python/runtime lain selain binary itu sendiri.

## 8. Risiko & Asumsi
| Risiko | Mitigasi |
|---|---|
| AI halusinasi finding | Finding hanya berasal dari output tool deterministic; AI tidak boleh membuat finding baru tanpa bukti tool |
| False positive tinggi dari nuclei | Verdict Engine doc 10: negative control + baseline + reproduksi 2x sebelum label `confirmed`; FP tetap disimpan untuk audit |
| False negative (vuln terlewat scanner) | Variant matrix, auth differential, coverage gap report per run (doc 10 §4b) |
| PoC script disalahgunakan / terlalu agresif | Safety Rules SR-01 s/d SR-10: katalog payload aman, Level 2 approval, Level 3 manual-only, tanpa payload destruktif |
| Target memblokir / rate-limit | Default rate-limit aman, user-agent jelas, opsi delay & proxy pool |
| Biaya LLM membengkak | Batch triage, cache hasil, model kecil untuk triage & model besar hanya untuk report |
| Duplikasi dengan ProjectDiscovery | Posisi sebagai orkestrator + AI layer, bukan menyaingi engine mereka (lihat Niche Strategy) |
