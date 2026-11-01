# 05 — Reference Repos

> **Catatan:** Daftar awal dari pengetahuan umum. Angka stars/status akan diverifikasi & dilengkapi dari hasil research yang sedang berjalan — jangan jadikan angka di file ini sebagai acuan final sebelum research selesai.

## A. ProjectDiscovery (referensi utama — ekosistem Go)
| Repo | Fungsi di Workflow Kita | Yang Dipelajari |
|---|---|---|
| `projectdiscovery/subfinder` | Recon subdomain (Fase 1) | Desain provider/source plugin passive |
| `projectdiscovery/httpx` | Probing & fingerprint (Fase 2) | Library + CLI dual mode |
| `projectdiscovery/nuclei` + `nuclei-templates` | Scanning (Fase 3) | Template engine YAML, matcher/extractor DSL |
| `projectdiscovery/dnsx` | DNS resolution (Fase 1-2) | — |
| `projectdiscovery/naabu` | Port scan (Fase 2, v0.5) | Integrasi nmap |
| `projectdiscovery/katana` | Crawling (Fase 2, v0.5) | Crawler Go modern, headless |
| `projectdiscovery/interactsh` | OOB detection (Fase 5, later) | Validasi blind vuln (SSRF, dll) |
| `projectdiscovery/pdtm` | Tool manager mereka | Cara distribusi/update banyak binary |
| `projectdiscovery/utils` | Library bersama PD | Pola shared library antar tool Go |

## B. Tools Go Lain (di luar PD)
| Repo | Fungsi | Catatan |
|---|---|---|
| `ffuf/ffuf` | Fuzzing konten/parameter (Fase 3, v0.5) | Go, sangat populer untuk directory fuzzing |
| `OJ/gobuster` | Directory/DNS brute-force | Alternatif ffuf |
| `lc/gau` | URL historis (Fase 1) | Passive URL collection |
| `tomnomnom/waybackurls`, `tomnomnom/gf`, `tomnomnom/anew`, `tomnomnom/qsreplace` | Utilitas pipeline klasik | Pelajari filosofi Unix-tool kecil yang bisa di-chain — inspirasi desain pipeline kita |
| `hahwul/dalfox` | XSS scanning (v0.5) | Contoh scanner Go niche satu kategori yang sukses |
| `edoardottt/awesome-hacker-search-engines` / list sejenis | Referensi sumber recon | Kurasi, bukan kode |

## C. AI Pentest / AI Bug Bounty (mayoritas Python — dipelajari arsitektur agent-nya, bukan bahasanya)
| Repo / Project | Yang Dipelajari |
|---|---|
| `GreyDGL/PentestGPT` | Pola reasoning / pentest task tree, human guidance |
| `usestrix/strix` | Multi-agent pentest, validasi dengan PoC nyata |
| `0x4m4/hexstrike-ai` | MCP server untuk security tools — referensi utama untuk mode MCP kita |
| `Nebula` / AI recon agent projects | Otomatisasi recon dengan LLM |
| _Akan dilengkapi dari research_ | Fokus: mana yang masih aktif 2025-2026, mana yang mati |

**Pertanyaan kunci research:** Apakah sudah ada AI pentest native Go yang serius? Jika belum/langka → itu validasi gap niche kita.

## D. Framework / Orchestrator Recon
| Repo | Catatan |
|---|---|
| `six2dez/reconFTW` | Workflow recon lengkap (bash) — pelajari urutan fasenya, bukan untuk ditiru bahasanya |
| `Osmedeus` | Framework workflow security (Go) — pelajari konsep workflow/step engine-nya |
| `epi052/recon-pipeline`, dll | Contoh pipeline sederhana |

## E. Library Go Pendukung
| Kebutuhan | Library Draft |
|---|---|
| CLI | `spf13/cobra`, `spf13/viper` |
| TUI | `charmbracelet/bubbletea`, `charmbracelet/lipgloss` |
| SQLite tanpa CGO | `modernc.org/sqlite` |
| Browser automation | `go-rod/rod` atau `chromedp/chromedp` |
| MCP | `modelcontextprotocol/go-sdk` |
| LLM | HTTP client OpenAI-compatible (tanpa framework di v0.1) |

## Prioritas Baca Kode (Top 5 untuk Mulai)
1. **nuclei** — template engine & cara mereka mengelola ribuan template komunitas
2. **httpx** — pola library+CLI yang bersih, paling mudah ditiru untuk tool pertama kita
3. **subfinder** — pola provider plugin untuk sumber passive
4. **hexstrike-ai** — pola MCP + tool registry untuk AI
5. **reconFTW** — urutan workflow recon yang sudah teruji di lapangan
