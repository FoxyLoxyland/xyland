# Xyland — AI Pentest Agent (Golang)

> **Status:** Design & Spec — 2 Nov 2026 (belum ada kode; repo ini berisi desain, skills, dan knowledge base agent)
> **Nama:** `xyland` (final)
> **Owner:** Ucup / FoxyLoxyland

**Xyland adalah pentest agent berbasis AI yang dibangun di Golang** — bukan sekadar wrapper scanner. Agent melakukan recon mendalam, membentuk hipotesis dari fingerprint target, memilih skill & knowledge CVE yang relevan saja (konteks efisien adalah prinsip inti), mengeksekusi pengujian lewat tool yang teruji, dan **hanya finding yang terverifikasi TRUE POSITIVE** yang dilanjutkan menjadi **PoC yang dikirim agent** beserta laporan siap submit ke HackerOne / Bugcrowd.

## Flow Inti
```
Recon Deep → Fingerprint & State Model → Hipotesis (diprioritaskan skor kesulitan)
→ Skill + CVE Selection (retrieval, maks 5) → Eksekusi (semua tercatat = receipt)
→ Verdict Engine (TP / FP / inconclusive) → PoC self-verifying → Report
```

## Kenapa Ada Project Ini?
Research kami (3 putaran, Nov 2026) menemukan kegagalan struktural yang berulang di agent pentest lain:
- **Validasi semu** — finding "tervalidasi" yang ternyata fabrikasi / false positive (jebakan respons 200 generik, validasi CORS pakai curl, hasil subtask yang tidak pernah dijalankan).
- **Context membengkak** — ±84% token agent habis untuk output tool mentah; tidak ada pemilihan konteks yang disiplin.
- **Tidak ada estimasi kesulitan** — agent kehabisan budget di jalur buntu dan melewatkan finding paling parah.
- **Lemah di access control & business logic** — karena target diperlakukan sebagai daftar URL, bukan state model antar-aktor.
Xyland dirancang spesifik untuk menutup keempatnya (lihat `docs/11-REVISED-DESIGN.md`).

## Isi Repo
| Bagian | Isi |
|---|---|
| `docs/` | Spec, workflow, arsitektur, desain agent, riset referensi, roadmap, strategi niche, reporting, keputusan, sistem PoC/validasi, ralat desain, context engineering, panduan skills & CVE |
| `skills/` | Library skill agent — format progressive disclosure: `_index.yaml` (metadata L1) + `SKILL.md` per skill (L2) + `references/` (L3). Skill baru masuk indeks hanya setelah terverifikasi di lab |
| `knowledge/cve/` | Kartu CVE terkurasi & ringkas (bukan salinan database CVE) + `_index.yaml`; diperbarui lewat pipeline KEV/EPSS/nuclei-templates |
| `knowledge/validation/` | Katalog validation rule per kelas vuln (pasangan wajib tiap skill) |
| `knowledge/classes/` | Catatan jebakan FP & checklist negatif per kelas vuln |
| `templates/` | Generator & contoh PoC script, template laporan |
| `examples/` | Contoh config, scope, dan `workflow.yaml` |

## Docs Utama
| File | Isi |
|---|---|
| [docs/01-SPEC.md](docs/01-SPEC.md) | Product spec: problem, user, scope, requirements (FR-01..FR-14) |
| [docs/02-WORKFLOW.md](docs/02-WORKFLOW.md) | Workflow end-to-end per fase |
| [docs/03-ARCHITECTURE.md](docs/03-ARCHITECTURE.md) | Arsitektur Go, struktur repo, data flow, storage |
| [docs/04-AI-AGENT-DESIGN.md](docs/04-AI-AGENT-DESIGN.md) | Desain AI agent dasar (sebagian ditimpa doc 11) |
| [docs/05-REFERENCE-REPOS.md](docs/05-REFERENCE-REPOS.md) | Repo referensi: ProjectDiscovery, Osmedeus, PentAGI, Strix, afrog, dll |
| [docs/06-ROADMAP.md](docs/06-ROADMAP.md) | Roadmap MVP v0.1 → v0.5 → v1.0 |
| [docs/07-NICHE-STRATEGY.md](docs/07-NICHE-STRATEGY.md) | Niche, positioning, model scale-up |
| [docs/08-REPORTING.md](docs/08-REPORTING.md) | Spesifikasi output & template laporan HackerOne / Bugcrowd |
| [docs/09-DECISIONS.md](docs/09-DECISIONS.md) | Log keputusan (ADR) |
| [docs/10-POC-VALIDATION.md](docs/10-POC-VALIDATION.md) | **Fitur inti:** PoC script + validation rules per finding, verdict TP/FP, cek false negative, safety rules SR-01..SR-10 |
| [docs/11-REVISED-DESIGN.md](docs/11-REVISED-DESIGN.md) | **Ralat & improve:** agent-first engine-guarded, receipt grounding, anti-200-trap, browser-realistic validation, difficulty estimation, state model, keamanan agent |
| [docs/12-CONTEXT-ENGINEERING.md](docs/12-CONTEXT-ENGINEERING.md) | 8 prinsip efisiensi konteks + budget token per turn |
| [docs/13-SKILLS-AND-CVE-KNOWLEDGE.md](docs/13-SKILLS-AND-CVE-KNOWLEDGE.md) | Cara skills & knowledge CVE diorganisasi, dipilih, dan diperbarui |

## Prinsip Utama
1. **Agent-first, engine-guarded** — AI mengemudi (hipotesis, eksekusi, adaptasi); engine deterministic memegang rem: scope, safety, verdict, budget.
2. **No exploit, no report** — tanpa PoC terverifikasi, finding tidak jadi laporan.
3. **Konteks adalah fitur** — state di SQLite, bukan di history chat; skill & CVE dimuat selektif berbasis fingerprint.
4. **Single binary Go** — jalan di VPS murah, tanpa runtime Python.
5. **Safe by default** — scope enforcement, redaksi pra-LLM, mutasi digate per level, hard budget cap.

## Catatan Keamanan & Etika
Tool ini dirancang hanya untuk pengujian **berizin**: program bug bounty dalam scope, lab sendiri, dan engagement pentest resmi. Safety rules lengkap di `docs/10-POC-VALIDATION.md` §5. Hasil run, data target, dan kredensial **tidak pernah** masuk repo ini (lihat `.gitignore`).
