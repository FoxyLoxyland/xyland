# 07 — Niche & Scale-Up Strategy (Draft Opsi)

_Belum diputuskan — file ini daftar opsi untuk dipilih setelah research selesai. Keputusan final dicatat di 09-DECISIONS.md._

## Strategi Dasar: Wrapper vs Engine Sendiri
| | A. Orchestrator di atas PD tools | B. Bangun engine dari nol |
|---|---|---|
| Time to MVP | Cepat (mingguan) | Lambat (bulanan) |
| Kualitas scan awal | Langsung setara nuclei dkk | Harus mengejar bertahun-tahun |
| Diferensiasi | Di AI layer, workflow, report | Di engine (sulit) |
| Risiko maintenance | Dependensi ke upstream | Semua ditanggung sendiri |
| **Rekomendasi draft** | ✅ **Mulai dari A**, tulis modul niche sendiri secara bertahap di atasnya | Hanya untuk modul spesifik niche nanti |

## Opsi Niche (pilih 1 fokus utama untuk v1.0)
| # | Niche | Argumen | Risiko |
|---|---|---|---|
| 1 | **Bug-bounty-specific workflow** (umum web) | Pasar terbesar, workflow H1/Bugcrowd belum ada yang Go+AI native | Kompetisi paling ramai |
| 2 | **API & GraphQL security** | API adalah permukaan serangan yang tumbuh; tools Go khusus API+AI masih sedikit; hunter API dibayar mahal | Butuh keahlian template/API testing mendalam |
| 3 | **Validation-first / anti-noise** — janji utama: "finding sedikit tapi confirmed" | Pain point terbesar hunter adalah noise; diferensiasi jelas & bisa dibuktikan | Validasi aman itu sulit secara teknis |
| 4 | **MCP-first AI tool** — tool dirancang untuk dipakai dari Claude/AI agent lain | Tren MCP sedang naik; distribusi lewat ekosistem AI | Pasar masih awal, edukasi user berat |
| 5 | **Self-hosted & privacy-first untuk hunter Indonesia/SEA** — jalan penuh di VPS sendiri, LLM gateway sendiri, laporan bilingual ID/EN | Kedekatan komunitas, bahasa, dan harga (LLM routing murah) | Pasar geografis lebih sempit |

**Kombinasi draft yang menarik:** #1 sebagai basis + #3 sebagai janji utama + #5 sebagai keunggulan distribusi awal. #2 bisa jadi spesialisasi modul di v1.0+. #4 sebagai fitur, bukan identitas utama.

## Model Scale-Up (opsi, bertahap)
1. **Open-source core** (CLI + pipeline) → komunitas, kredibilitas, kontribusi template
2. **Template & modul premium** untuk niche terpilih (mis. paket template API)
3. **Managed / SaaS** (later): scheduled scanning di infrastruktur kita untuk tim kecil
4. **Content & komunitas**: tulis write-up hunting memakai tool sendiri → distribusi organik di komunitas bug bounty Indonesia & global

## Go-to-Market Awal (murah & realistis)
- Pakai tool untuk hunting sendiri dulu; setiap finding valid = studi kasus & konten.
- Rilis GitHub dengan README bilingual (EN utama, ID pendukung), demo GIF 1 command → report.
- Bagikan ke komunitas: Discord/Telegram bug bounty ID, X/Twitter infosec, grup kampus/komunitas Go Indonesia.
- Kumpulkan feedback dari 5-10 hunter pertama sebelum menambah fitur besar.

## Metrik yang Dipantau
- Waktu dari target → draft laporan (target: turun drastis vs manual)
- % finding `confirmed` dari total raw finding (kualitas triage)
- Jumlah user GitHub (stars memang vanity, tapi fork & issue lebih berarti)
- Retensi pribadi: apakah kita sendiri masih memakai tool ini tiap hunting? Jika tidak, ada yang salah.
