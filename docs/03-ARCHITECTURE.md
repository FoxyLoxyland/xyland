# 03 — Architecture (Golang)

## High-Level
```
                        ┌─────────────────────────┐
   User (CLI/TUI) ─────▶│  xyland CLI (cobra)     │
                        └──────────┬──────────────┘
                                   │
                        ┌──────────▼──────────────┐
                        │  Orchestrator / Pipeline │
                        │  (fase, checkpoint, job) │
                        └──┬────────┬────────┬─────┘
                           │        │        │
              ┌────────────▼─┐ ┌────▼─────┐ ┌▼──────────────┐
              │ Tool Runner  │ │ AI Agent │ │ Storage       │
              │ subfinder,   │ │ planner, │ │ SQLite + file │
              │ httpx,nuclei │ │ triage,  │ │ per job       │
              │ katana, ffuf │ │ report   │ │               │
              └──────┬───────┘ └────┬─────┘ └───────────────┘
                     │              │
                     │       ┌──────▼───────────────────┐
                     │       │ LLM Gateway (OpenAI-     │
                     │       │ compatible API)          │
                     │       │ → 9Router self-hosted /  │
                     │       │   OpenAI / Claude / dll  │
                     │       └──────────────────────────┘
                     ▼
                  Target
               (in-scope only)
```

## Struktur Repo yang Disarankan
```
xyland/
├── cmd/
│   └── xyland/            # main.go — entrypoint CLI (cobra)
├── internal/
│   ├── cli/               # command definitions: scan, recon, report, resume
│   ├── orchestrator/      # pipeline, checkpoint, job lifecycle
│   ├── tools/             # wrapper tiap tool eksternal
│   │   ├── subfinder/
│   │   ├── httpx/
│   │   ├── nuclei/
│   │   ├── katana/        # v0.5
│   │   └── ffuf/          # v0.5
│   ├── agent/             # AI agent: planner, triage, validator, reporter
│   ├── llm/               # client OpenAI-compatible, routing, token limiter
│   ├── storage/           # SQLite (modernc.org/sqlite — tanpa CGO) + file store
│   ├── scope/             # scope parser & enforcement
│   ├── report/            # generator laporan H1 / Bugcrowd
│   └── config/            # viper: YAML + env + flags
├── pkg/
│   └── types/             # tipe publik: Asset, Finding, Job (dipakai library mode)
├── templates/
│   ├── nuclei/            # template terkurasi / tambahan sendiri
│   └── reports/           # template laporan .md.tmpl
├── examples/
│   ├── config.example.yaml
│   └── scope.example.txt
├── docs/
├── go.mod
└── README.md
```

## Keputusan Teknis Awal (draft)
| Area | Pilihan Draft | Alasan | Alternatif |
|---|---|---|---|
| CLI framework | `spf13/cobra` + `spf13/viper` | Standar de facto tools Go (juga dipakai ProjectDiscovery) | `urfave/cli` |
| Cara integrasi tool PD | Prioritas 1: pakai sebagai Go library jika tersedia; Prioritas 2: panggil binary eksternal via Tool Runner | Library = lebih rapi & single binary; binary eksternal = lebih mudah update | Hybrid per tool (keputusan final setelah research) |
| Storage | SQLite file per workspace + JSON export | Portabel, query dedup mudah, tanpa server | JSON flat saja untuk MVP super-minimal |
| LLM client | HTTP client ke endpoint OpenAI-compatible | Kompatibel dengan 9Router (gateway user), OpenAI, OpenRouter, Ollama, dll | SDK resmi per provider (hindari lock-in) |
| AI framework | Tanpa framework berat di v0.1 — tool-calling manual terstruktur (JSON schema) | Kontrol penuh, dependensi minim, mudah debug | `langchaingo`, framework agent Go lain (evaluasi di research) |
| TUI | Spinner/progress sederhana dulu; `charmbracelet/bubbletea` di v0.5 | MVP fokus ke pipeline, bukan tampilan | — |
| Browser automation (bukti/screenshot) | `go-rod/rod` (v0.5) | Pure Go control atas Chrome, populer | `chromedp` |
| Concurrency | Worker pool dengan `errgroup`, rate-limiter per host | Pola standar scanning Go | — |
| MCP mode (v1.0) | `modelcontextprotocol/go-sdk` sebagai MCP server | Tool bisa dipakai langsung dari AI client | — |

## Interface Inti — Tool
Semua tool eksternal dibungkus interface seragam, agar fase pipeline tidak peduli detail tool:

```go
type Tool interface {
    Name() string
    // Check memastikan binary/library & config siap
    Check(ctx context.Context) error
    // Run menjalankan tool untuk job & fase tertentu, menulis hasil terstruktur
    Run(ctx context.Context, in Input) ([]Finding, error)
}
```
Pola yang sama dipakai untuk tool baru: implementasi interface ini = tool langsung bisa dipakai orchestrator.

## Data Model Inti (sketsa)
```go
type Job struct {
    ID        string
    Targets   []string
    Scope     Scope
    Mode      string // passive | standard | deep
    Phase     string // checkpoint terakhir
    CreatedAt time.Time
}

type Asset struct {
    Host, URL, IP, Title, Tech string
    StatusCode int
    Interesting bool
}

type Finding struct {
    ID, JobID, AssetURL string
    SourceTool, TemplateID string
    Title, Severity string
    Evidence   Evidence // request, response (redacted), matcher
    Priority   int      // dari AI triage
    Confidence int
    Status     string // raw | triaged | confirmed | likely | needs-manual-check | false-positive
}
```

## Config (contoh)
Lihat `examples/config.example.yaml` — dibuat bersama docs ini.

## Non-Goals Arsitektur v0.1
- Bukan microservices. Satu binary, satu proses, storage lokal.
- Bukan distributed scanning. Scaling awal = jalan di 1 VPS dengan baik.
- Plugin system dinamis (`.so`) ditunda — cukup interface Go + template file.
