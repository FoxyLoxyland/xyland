# 12 — Context Engineering (Efisiensi Konteks Agent)

> Karena yang mengeksekusi adalah AI, **pemilihan konteks adalah fitur produk, bukan detail implementasi.**
> Bukti yang mendasari (Putaran 3): akurasi model menurun monoton terhadap panjang input (context rot);
> ±84% token per turn agent pentest adalah *observation* hasil tool; prompt fokus ratusan token mengalahkan
> prompt ratusan ribu token; summarization LLM menghaluskan detail kegagalan & memperpanjang trajectory.

## 8 Prinsip (mengikat untuk semua kode agent)

| # | Prinsip | Implementasi Xyland |
|---|---|---|
| P-1 | **State di luar LLM** | Semua fakta (aset, hipotesis, hasil tes, verdict) hidup di SQLite. Context window hanya *salinan kerja* yang bisa dibuang & dibangun ulang dari state kapan pun. |
| P-2 | **Observation masking > summarization** | Output tool lama diganti placeholder terstruktur: `[obs #123 nuclei: 47 findings, 3 high — full: artifacts/obs123.json]`. Ringkasan LLM hanya untuk transisi fase, dan tidak boleh menghaluskan kegagalan (exit code & error disimpan verbatim di placeholder). |
| P-3 | **Progressive disclosure untuk skill** | Skill dimuat 3 lapis (lihat doc 13): L1 metadata ±100 token selalu tersedia sebagai indeks; L2 isi skill (<5k token) hanya saat skill terpilih; L3 file referensi hanya saat langkah spesifik membutuhkannya. Dilarang memuat semua skill sekaligus (kasus HexStrike: 151 tool sekaligus → tool-selection collapse). |
| P-4 | **Retrieval just-in-time berbasis fingerprint** | Pemilihan skill & CVE dipicu fingerprint terukur (tech stack, header, perilaku auth, jenis endpoint), bukan tebakan bebas model. Model menerima *daftar kandidat hasil retrieval* (maks 5, pola Strix) lalu memilih — bukan mencari di seluruh library sendiri. |
| P-5 | **Budget konteks ditegakkan engine** | Alokasi keras per turn (lihat tabel budget). Engine menolak menyusun prompt yang melampaui alokasi; hipotesis punya budget sendiri (doc 11 §4). |
| P-6 | **Sub-agent context terisolasi** | Tugas eksplorasi lebar (mis. JS analysis di banyak host) dijalankan sub-agent dengan context sendiri; yang kembali ke agent utama hanya kesimpulan terstruktur + pointer artifact, bukan transkrip. |
| P-7 | **Catatan terstruktur, bukan history mentah** | Di akhir tiap langkah, agent menulis `note` terstruktur ke state (apa dicoba, bukti, kesimpulan, next). Rekonstruksi konteks sesi berikutnya = system + state summary + notes terakhir, bukan replay percakapan. |
| P-8 | **Deterministik bila bisa** | Keputusan yang bisa dihitung kode (dedup, skor kesulitan, verdict, diff baseline) tidak memakan token sama sekali. Token hanya untuk penilaian yang memang butuh model. |

## Budget Konteks per Turn Agent (draft, dikalibrasi dari evaluasi)
| Komponen | Alokasi | Catatan |
|---|---|---|
| System + aturan safety | ±1.500 token | Tetap, versi tercatat |
| Indeks skill (L1 semua skill) | ±100 token × jumlah skill terindeks | Hanya metadata |
| State summary target (aset menarik + state model ringkas) | ≤ 3.000 token | Dibangun dari SQLite, bukan ditulis model |
| Hipotesis aktif + notes terakhir | ≤ 2.000 token | |
| Skill terpilih (L2, maks 2 skill/turn) | ≤ 8.000 token | |
| CVE cards relevan (maks 5) | ≤ 2.500 token | Format kartu ringkas, doc 13 |
| Observasi langkah ini (terpotong terstruktur) | ≤ 6.000 token | Output mentah ke artifact, bukan ke prompt |
| **Total kerja per turn** | **±23.000 token** | Sisanya ruang bernapas model — sengaja jauh di bawah limit window |

## Anti-Pattern (dilarang, masing-masing ada bukti kegagalannya)
- Menempel output scan mentah ribuan baris ke prompt.
- System prompt raksasa berisi semua playbook sekaligus.
- Membiarkan agent "mengingat" lewat percakapan panjang lintas fase.
- Summarization berantai (summary dari summary) tanpa kembali ke artifact asli — saat detail dibutuhkan, ambil dari artifact (P-1), bukan dari ringkasan.
- Mengirim data target mentah ke LLM tanpa redaksi (doc 11 §6).
