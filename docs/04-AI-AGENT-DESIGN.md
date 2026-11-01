# 04 — AI Agent Design

## Prinsip
AI di project ini adalah **orkestrator & analis**, bukan scanner. Scanner = tool deterministic. Ini membedakan kita dari AI pentest generik yang rawan halusinasi.

## Peran AI per Titik (hanya 4 titik di v0.1)
| # | Titik | Input AI | Output AI | Model yang Disarankan |
|---|---|---|---|---|
| 1 | Template selection | Tech stack aset | Set template nuclei yang relevan | Kecil / murah |
| 2 | Triage | Batch raw findings | Skor prioritas, kategori, alasan singkat | Kecil-menengah |
| 3 | Validation planning | Finding prioritas tinggi | Langkah validasi read-only + penilaian bukti | Menengah-besar |
| 4 | Report drafting | Finding confirmed + bukti | Draft laporan platform | Besar (kualitas tulisan) |

Di luar 4 titik ini, **tidak ada panggilan LLM** — menghemat biaya & menjaga determinisme.

## Pola Agent
- **Bukan** autonomous agent bebas (loop ReAct tanpa batas) di v0.1.
- Pola yang dipakai: **fixed pipeline + LLM di node keputusan** — dapat diprediksi, mudah di-debug, biaya terkendali.
- v0.5+: pertimbangkan planner agent terbatas untuk chaining antar finding, dengan batas langkah (`max_steps`), batas token (`max_tokens_per_job`), dan timeout keras.

## Tool-Calling Contract
Jika nanti agent diberi akses memanggil tool:
- Setiap tool call harus tervalidasi terhadap scope & mode saat ini.
- Tool call dicatat di audit log: siapa (AI/user), tool apa, argumen, hasil ringkas.
- Tool yang mengubah state / bersifat eksploitasi aktif: **wajib human approval**, tidak ada pengecualian di v0.1–v0.5.

## Anti-Halusinasi Rules (wajib di system prompt & di kode)
1. AI tidak boleh membuat finding, URL, parameter, atau bukti yang tidak ada di input.
2. Setiap klaim di laporan harus bisa ditelusur ke `Finding.Evidence`.
3. Jika bukti kurang, AI wajib memberi status `needs-manual-check`, bukan mengarang kesimpulan.
4. Output AI selalu JSON terstruktur (schema divalidasi di kode) untuk triage; teks bebas hanya untuk draft laporan.

## LLM Gateway & Routing
- Client berbicara protokol **OpenAI-compatible** (`/v1/chat/completions`).
- Ini membuat tool langsung kompatibel dengan:
  - Gateway self-hosted user (9Router di VPS — multi-model routing, proxy pool)
  - OpenAI, OpenRouter, provider kompatibel lain, Ollama lokal
- Config memisahkan model per peran: `triage_model`, `report_model`, dll — model murah untuk volume, model bagus untuk tulisan akhir.
- Fallback: jika LLM tidak tersedia, pipeline tetap selesai tanpa AI (ranking default dari severity tool).

## Memory Agent
- Jangka pendek: konteks satu job (aset, finding, keputusan triage sebelumnya) — disimpan di storage job, bukan hanya di prompt.
- Jangka panjang (v1.0): catatan per program/target (mis. "program X menolak report jenis Y") yang dimasukkan sebagai konteks triage. Belum di v0.1.

## Evaluasi Kualitas AI
- Siapkan dataset kecil manual: 20-30 raw finding contoh dengan label prioritas dari manusia.
- Ukur: apakah ranking AI mendekati ranking manusia? Apakah ada finding `confirmed` tanpa bukti? (target: 0)
- Evaluasi ini dijalankan setiap ganti model / ganti prompt.
