# 15 — Catatan Implementasi v0.1

Status: **kode berjalan** (build bersih `go build ./...`, `go vet` bersih, binary ±17 MB, CGO nonaktif).

## Yang sudah terimplementasi (sesuai docs 11–14 & riset putaran 4)

| Modul | Isi |
|---|---|
| `internal/engine` | State machine 9 state + DONE; State Brief per state (goal, aksi sah, artefak, gate) |
| `internal/store` | Ledger SQLite (modernc, pure Go): jobs, executions (receipt), assets, findings, notes; state job = checkpoint untuk resume |
| `internal/scope` | Scope file (+ allow / − deny / pola *.domain) ditegakkan sebelum recon |
| `internal/agent` | Orkestrator flow; hipotesis + skor difficulty heuristik; bantuan LLM opsional untuk menilai hipotesis (tidak menentukan verdict) |
| `internal/skills` | Retrieval deterministik dari `_index.yaml` (maks 5, urut skor lalu biaya konteks) |
| `internal/knowledge` | Pencocokan kartu CVE ke fingerprint — kandidat saja, kata generik ("server", "windows") disaring |
| `internal/llm` | Klien OpenAI-compatible (9Router/dll) via env; metering token dicatat; antarmuka meniru bentuk ChatModel Eino |
| `internal/tools` | Prober HTTP bawaan (tanpa ikuti redirect), fingerprint (server/header/cookie/tech), runner binary eksternal bila ada di PATH |
| `internal/validate` | Kemiripan body (anti-200-trap), baseline path acak |
| check bawaan | exposed-files ([core]/ref:/pola .env), reflected-XSS (marker, verdict maksimal *likely* — konfirmasi DOM menyusul), open-redirect (marker domain sendiri), misconfig (observasi deterministik) — semua repeat 2× + kontrol/baseline |
| `internal/poc` | poc.py self-verifying (exit 0 TP / 2 FP / 3 inconclusive) untuk exposure, xss-reflected, open-redirect |
| `internal/report` | report.md: hanya confirmed/likely di bagian Findings; sisanya di Catatan Validasi |
| `internal/tui` + `internal/theme` | Dashboard bubbletea: strip progres flow, panel aset & findings; snapshot statis bila bukan TTY. Palet tunggal di `theme` ("midnight lab": mint #3DFFA2, cyan #39C6F3, violet #9B7CFF) |

## Keputusan build yang diambil

- **SQLite di-pin `modernc.org/sqlite v1.34.5`** + `GOTOOLCHAIN=local` (Go 1.24): versi terbaru modernc menuntut Go ≥ 1.26 dan menarik toolchain baru — untuk v0.1 reprodusibilitas lebih penting; evaluasi ulang saat upgrade Go.
- **Eino belum di-vendor**: lapisan LLM ditulis sebagai klien ramping berantarmuka kompatibel-bentuk; adapter Eino menyusul setelah spike 9Router (riset putaran 4 §belum-terverifikasi) selesai — menghindari pohon dependensi besar sebelum terbukti perlu.
- **Nuclei dkk. sebagai binary eksternal dulu** (PATH), bukan library: sesuai peringatan riset bahwa nuclei CLI-first & library-nya tipis; integrasi library dijadwalkan dengan interface pembungkus + pin versi.

## Uji yang sudah dijalankan

Lab lokal (server Python rentan + jebakan SPA-200): `.git/config` & `.git/HEAD` → **confirmed**; `/.env` versi SPA → **false-positive** (jebakan tertolak dengan benar); open-redirect → **confirmed**; reflected XSS → **likely**; misconfig → confirmed/low. PoC hasil generate dijalankan ulang dan mencetak `CONFIRMED_TRUE_POSITIVE` (exit 0).

## Berikutnya

1. Executor browser (rod) untuk menaikkan reflected-XSS `likely → confirmed` + check stored/DOM XSS.
2. Adapter Eino + spike structured-output di 9Router; streaming token budget di TUI.
3. Wrapper library ProjectDiscovery dengan interface + pin (nuclei/httpx/katana) & spike CGO katana vs modernc.
4. Check IDOR/auth & SQLi detection dari validation rules yang sudah ada di `knowledge/validation/`.
5. Eval harness sesuai ambang riset putaran 4 (Juice Shop/DVWA/vulhub).

## Update v0.2 — fitur per-fitur + test + CI (3 Nov 2026)

- **Check baru**: SQLi detection (error-based terkonfirmasi 2/2 + boolean-differential untuk *likely*; deteksi saja, tanpa ekstraksi), path traversal (marker `/etc/passwd` + kontrol nama jinak), CORS (refleksi Origin asing; berkredensial = confirmed/medium). Ketiganya lengkap dengan generator PoC self-verifying.
- **Test**: unit test untuk engine, scope, validate, store, skills, knowledge, poc + **integration test end-to-end** (`internal/agent/agent_test.go`) melawan lab `httptest` yang meniru target rentan + jebakan SPA-200. `go test ./...` hijau semua paket.
- **CI**: `.github/workflows/ci.yml` (GitHub Actions): gofmt check → `go vet` → `go test ./...` → build → smoke test CLI (`version/flow/skills/cve`). Go 1.24, `GOTOOLCHAIN=local`, `CGO_ENABLED=0` — sama dengan `Makefile` lokal (`make ci`).
- Uji live tambahan vs lab lokal yang diperluas: 9 verdict sesuai harapan (termasuk sqli/traversal/cors confirmed, `.env` jebakan tetap false-positive).

## Update v0.3 — MVP spec §4 ditutup (3 Nov 2026)

Semua item "In Scope — v0.1 (MVP)" di `docs/01-SPEC.md` §4 sekarang tercentang:

- **Multi-target**: `-t` koma-terpisah atau `--targets-file`; job id kini unik per run (akhiran acak).
- **Konfigurasi YAML** (FR-07): `internal/config` + `examples/xyland.yaml`; env tetap menimpa file. `--config` untuk path lain.
- **Recon eksternal beneran jalan**: httpx (JSONL → aset + tech) & subfinder (subdomain in-scope diprobe, maks 15) via PATH dengan receipt; parsernya diuji unit.
- **Nuclei ingestion**: severity critical/high/medium, JSONL → kandidat finding (critical/high = *likely*, medium = *inconclusive*; verdict final tetap milik rule xyland), receipt terikat.
- **Triage & dedup** (FR-04): dedup kelas+URL (status terkuat menang, data mentah tetap di ledger), skor prioritas deterministik severity × kekuatan verdict, laporan terurut prioritas.
- **Output JSON + Markdown** (spec §4) dan **Coverage Gap** (FR-14) di laporan: URL berparameter ditemukan vs teruji vs belum teruji.
- **IDOR auth-differential**: aktif hanya dengan `--auth-a/--auth-b`; pola A-baseline / B-lintas-pemilik / kontrol id tak dikenal; PoC membaca sesi dari env (tanpa kredensial di file).
- **--dry-run** (FR-09): berhenti di RETRIEVAL, nol finding, state job berhenti di RETRIEVAL.

Test bertambah: config, parser httpx/subfinder/nuclei, dedup/prioritas/JSON report, integrasi tool eksternal palsu (fake binaries di PATH), IDOR dua sesi, dan dry-run — semua hijau. Demo live: IDOR `/profile` confirmed (sementara `/item` jujur *likely* karena kontrolnya sendiri ambigu), report.json terbit, coverage 5/5.

## Update v0.5 — pasca-MVP: browser executor, katana, chaining, MCP (3 Nov 2026)

- **Executor browser (rod v0.116.2)**: spike lolos — Chromium terunduh & berjalan headless. `internal/browser`: konfirmasi eksekusi DOM untuk reflected-XSS (payload SVG onload memasang marker `data-xyland` pada body; terverifikasi dengan kontrol negatif). Verdict naik *likely → confirmed* hanya dengan bukti eksekusi ini, plus **screenshot bukti** PNG ke `evidence/`. Nonaktifkan dengan `XYLAND_BROWSER=off`. Test browser sungguhan ada dan di-skip anggun bila Chromium tak tersedia.
- **Katana ingestion**: crawl depth 2, endpoint berparameter (in-scope) digabung ke kolam URL uji semua check; parser teruji + receipt tercatat.
- **Attack chaining**: bagian khusus di laporan — saran deterministik dari kombinasi finding (mis. XSS + cookie tanpa HttpOnly → pencurian sesi; SQLi → pengingat Level 3). Dilabeli jelas sebagai saran, bukan finding.
- **Mode MCP server** (`xyland mcp`): JSON-RPC 2.0 stdio, tools `xyland_flow`, `xyland_skills`, `xyland_cves`, `xyland_scan` (dengan opsi dry_run) — xyland bisa dipanggil dari klien AI lain; scope & safety tetap ditegakkan agent. Teruji unit (initialize/list/call) + smoke test live.
- Demo live: reflected-XSS kini **confirmed via browser** (sebelumnya mentok likely), screenshot tersimpan, chaining muncul di laporan, MCP menjawab initialize & tools/list dengan benar.
- Masih di luar jangkauan sesi ini: adapter Eino (lapisan LLM saat ini cukup; adapter menyusul spike 9Router), ffuf/directory fuzzing, mode monitoring terjadwal di VPS, screenshot untuk kelas finding selain XSS.
