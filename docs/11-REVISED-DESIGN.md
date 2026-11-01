# 11 — Ralat & Improve Desain: Xyland adalah Pentest Agent

> Revisi arah berdasarkan research Putaran 1–3 (lihat halaman research & `05-REFERENCE-REPOS.md`).
> Dokumen ini **menimpa** asumsi lama bila bertentangan. Tanggal: 2 Nov 2026.

## Ralat Utama

| # | Asumsi Lama (v0.1 draft) | Ralat |
|---|---|---|
| R-1 | "Deterministic first, AI second" — AI hanya di 4 titik pasif (pilih template, triage, jelaskan, draft) | **Agent-first, engine-guarded.** AI adalah *executor* yang membentuk hipotesis, memilih skill, menjalankan tool, dan beradaptasi dari hasil — tapi setiap klaim & aksi dibatasi engine deterministic (scope, safety, verdict, budget). AI mengemudi, engine yang memegang rem dan rambu. |
| R-2 | Nama codename `huntgo` | **Final: `xyland`** (keputusan user, 2 Nov 2026). Repo GitHub: `xyland`. |
| R-3 | Tool dipanggil dari pipeline tetap (`flow` kaku) | Pipeline tetap hanya untuk *fase besar* (scope→recon→enum). Di dalam fase pengujian, agent bebas menyusun langkah berdasarkan hipotesis (graph runtime), seperti pelajaran dari Strix — tapi dengan batas langkah, budget, dan checkpoint per langkah. |
| R-4 | Validasi = rule + PoC saja sudah cukup | Research Putaran 3 membuktikan validasi tool lain semu. Validasi xyland ditambah 3 lapis di §3 dokumen ini: *receipt grounding*, *anti-200-trap*, *browser-realistic execution*. |
| R-5 | Tidak ada konsep kesulitan tugas | Ditambah **Difficulty Estimation** (§4) — kegagalan planning adalah tipe kegagalan dominan agent pentest menurut literatur. |
| R-6 | Context = history percakapan + ringkasan | Diganti total oleh desain di `12-CONTEXT-ENGINEERING.md`: state terstruktur di SQLite, observation masking, progressive disclosure untuk skill. |
| R-7 | Target diperlakukan sebagai daftar URL | Ditambah **state model** (§5) untuk IDOR & business logic: aktor, sesi, objek, transisi. |

## Flow Inti Xyland (yang diminta user)

```
RECON DEEP ──► FINGERPRINT & STATE MODEL ──► AGENT MEMBENTUK HIPOTESIS
                                                    │  (skor: impact × confidence ÷ difficulty)
                                                    ▼
                              SKILL + CVE SELECTION (context-efficient, lihat doc 12 & 13)
                                                    │
                                                    ▼
                              EKSEKUSI PENGUJIAN (tool via engine, semua tercatat = receipt)
                                                    │
                                          ┌─────────┴─────────┐
                                          │  VERDICT ENGINE     │
                                          │  TP / FP / inconcl. │
                                          └─────────┬─────────┘
                                          hanya TP ▼
                              AGENT MENGHASILKAN & MENGIRIM PoC (poc.py self-verifying)
                                                    │
                                                    ▼
                              REPORT (bukti + PoC + verdict, siap submit)
```

Kunci kecepatan menemukan vuln: **hipotesis terarah dari fingerprint**, bukan scan membabi buta. Setiap hipotesis yang gagal wajib meninggalkan *negative result* tercatat (sudah dites apa, dengan cara apa, hasilnya apa) — agent dilarang mengulang tes yang sama dan dilarang menutup target sebelum checklist negatif lengkap (anti premature-closure, pelajaran dari agent yang berhenti di 401 pertama lalu melewatkan finding tersevere).

## 3 Lapis Tambahan Validasi (dari Putaran 3)

### L-1 Receipt Grounding
- Setiap subtask/finding di SQLite punya kolom `execution_id`. Status `done` **ditolak engine** bila tidak ada baris tool-execution yang terikat (command, waktu, exit code, hash output).
- Finding hanya bisa lahir dari output tool yang tersimpan (artifact hash), tidak pernah dari teks bebas agent. Ini membunuh failure mode "phantom result" (PentAGI issue #457).

### L-2 Anti-200-Trap
- Baseline diff dihitung dari **konten** (content-type, panjang ternormalisasi, marker unik, struktur DOM/JSON), bukan status code.
- Bila respons payload ≈ respons baseline ≈ respons path ngawur (SPA catch-all), verdict otomatis maksimal `inconclusive` dan agent diberi tahu eksplisit: "target membalas seragam — jangan simpulkan dari status/body generik".

### L-3 Browser-Realistic Execution
- Kelas vuln yang semantiknya milik browser (XSS, CORS, open redirect dengan interaksi user, clickjacking) **wajib** divalidasi lewat browser sungguhan (rod), bukan curl/httpx. Curl mengabaikan same-origin policy — itulah akar FP CORS terkenal dari Strix.
- Rule di katalog (doc 10) kini punya field `executor: http | browser`.

## 4. Difficulty Estimation & Pruning
Setiap hipotesis diberi skor oleh engine (bukan perasaan model):
```
priority = (impact_estimasi × confidence_bukti_awal) / difficulty
difficulty = f(horizon_langkah, beban_context, riwayat_sukses_kelas_ini_di_target_serupa)
```
- Budget token & langkah per hipotesis ditegakkan engine (`max_tokens_per_hypothesis`, `max_steps`).
- Hipotesis di bawah ambang prioritas di-*prune* (dicatat alasannya), bukan dikejar sampai context habis.
- Agent boleh mengajukan naik budget hanya dengan bukti kemajuan (evidence baru), bukan janji.

## 5. State Model untuk IDOR & Business Logic
Storage menyimpan, per target: aktor (anon / user A / user B / admin bila ada), kredensial uji milik sendiri, objek yang dibuat/ditemukan tiap aktor, dan transisi yang diizinkan. Skill IDOR/auth bekerja di atas model ini (auth differential, doc 10 §4b), bukan menebak ID secara acak. Inilah jawaban atas kelemahan semua agent di benchmark: mereka gagal justru di access control & logika stateful.

## 6. Keamanan Agent Sendiri (baru, dari Putaran 3)
| Ancaman | Mitigasi Engine |
|---|---|
| Prompt injection dari konten target (halaman/response berisi instruksi ke agent) | Semua konten target diperlakukan sebagai **data**, dibungkus delimiter, dan tidak pernah boleh memicu tool call di luar rencana; tool call selalu divalidasi ke rencana + scope |
| Data target bocor ke LLM cloud | **Redaksi pra-LLM**: token, cookie, PII, dan kredensial diredaksi/diganti placeholder sebelum masuk prompt; mode full-local (Ollama/9Router) tersedia |
| Agent merusak target (kasus Strix menghapus admin) | Mutasi (POST/PUT/DELETE yang mengubah state) digate per safety level (doc 10 §5); Level 2 approval user, Level 3 manual-only — ditegakkan **kode**, bukan prompt |
| Tool-calling model tidak patuh | **Conformance suite** sebelum run: model harus lulus tes tool-call dasar (format JSON, ID unik, tidak mengarang hasil) di provider tsb. Model yang gagal = run dibatalkan dengan pesan jelas |
| Biaya tak terkendali / meter tidak akurat | Metering dihitung engine dari respons provider per panggilan; **hard budget cap** per job (USD/token) — engine menghentikan run saat cap tercapai, dashboard bukan satu-satunya sumber angka |

## 7. Apa yang TIDAK Berubah
Single binary Go, storage SQLite, LLM OpenAI-compatible (9Router/Ollama/provider lain), gerbang "hanya TP yang boleh jadi laporan", scope enforcement, dan katalog PoC per kelas (doc 10) tetap berlaku penuh.
