// Package cli adalah antarmuka baris perintah xyland (cobra).
package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/FoxyLoxyland/xyland/internal/agent"
	"github.com/FoxyLoxyland/xyland/internal/config"
	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/knowledge"
	"github.com/FoxyLoxyland/xyland/internal/llm"
	"github.com/FoxyLoxyland/xyland/internal/skills"
	"github.com/FoxyLoxyland/xyland/internal/theme"
	"github.com/FoxyLoxyland/xyland/internal/tui"
)

var version = "0.1.0-dev"

// repoRoot menebak lokasi skills/ & knowledge/ : env XYLAND_HOME, lalu direktori
// kerja bila berisi skills/, lalu relatif terhadap biner.
func repoRoot() string {
	if v := os.Getenv("XYLAND_HOME"); v != "" {
		return v
	}
	if _, err := os.Stat(filepath.Join("skills", "_index.yaml")); err == nil {
		wd, _ := os.Getwd()
		return wd
	}
	return "."
}

func Execute() error {
	root := &cobra.Command{
		Use:   "xyland",
		Short: "xyland — AI pentest agent untuk bug bounty (Go)",
		Long:  theme.Banner.Render(theme.Logo) + "\n  AI pentest agent: recon deep → hipotesis → validasi TP → PoC → report",
	}
	root.AddCommand(scanCmd(), resumeCmd(), skillsCmd(), cveCmd(), tuiCmd(), flowCmd())
	root.AddCommand(&cobra.Command{
		Use: "version", Short: "Tampilkan versi",
		Run: func(cmd *cobra.Command, args []string) { fmt.Println("xyland", version) },
	})
	return root.Execute()
}

func printEvent(ev agent.Event) {
	state := theme.Agent.Render(fmt.Sprintf("%-12s", string(ev.State)))
	switch ev.Kind {
	case "state":
		fmt.Println("\n" + theme.Chip.Render("FLOW") + " " + theme.Title.Render("→ "+ev.Msg))
	case "tool":
		fmt.Println("  " + state + theme.Tool.Render("⚙ ") + ev.Msg)
	case "agent":
		fmt.Println("  " + state + theme.Agent.Render("◆ ") + ev.Msg)
	case "verdict":
		fmt.Println("  " + state + theme.Warn.Render("⚖ ") + ev.Msg)
	case "warn":
		fmt.Println("  " + state + theme.Warn.Render("! ") + ev.Msg)
	default:
		fmt.Println("  " + state + theme.Muted.Render("· ") + ev.Msg)
	}
}

func scanCmd() *cobra.Command {
	var target, scopeFile, outDir, resume, targetsFile, configPath, authA, authB string
	var dryRun bool
	c := &cobra.Command{
		Use:   "scan",
		Short: "Jalankan flow penuh: scope → recon → hipotesis → eksekusi → verdict → PoC → report",
		RunE: func(cmd *cobra.Command, args []string) error {
			// daftar target: -t boleh koma-terpisah, atau --targets-file (satu URL per baris)
			var targets []string
			if target != "" {
				for _, t := range strings.Split(target, ",") {
					if t = strings.TrimSpace(t); t != "" {
						targets = append(targets, t)
					}
				}
			}
			if targetsFile != "" {
				raw, err := os.ReadFile(targetsFile)
				if err != nil {
					return err
				}
				for _, line := range strings.Split(string(raw), "\n") {
					if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
						targets = append(targets, line)
					}
				}
			}
			if len(targets) == 0 && resume == "" {
				return fmt.Errorf("wajib: -t/--target atau --targets-file (atau --resume <job-id>)")
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			if outDir == "results" && cfg.Scan.Out != "" {
				outDir = cfg.Scan.Out
			}
			llmCfg := llm.Config{BaseURL: cfg.LLM.BaseURL, APIKey: cfg.LLM.APIKey, Model: cfg.LLM.Model}
			fmt.Println(theme.Banner.Render(theme.Logo))
			fmt.Println(theme.Muted.Render("  AI pentest agent — no exploit, no report"))
			root := repoRoot()
			run := func(tgt, resumeID string) error {
				jobID, err := agent.Run(context.Background(), agent.Options{
					Target: tgt, ScopeFile: scopeFile, OutDir: outDir,
					SkillsDir: filepath.Join(root, "skills"), CVEDir: filepath.Join(root, "knowledge", "cve"),
					ResumeID: resumeID, DryRun: dryRun, AuthA: authA, AuthB: authB, LLM: llmCfg,
					OnEvent: printEvent,
				})
				if err != nil {
					return err
				}
				fmt.Println("\n" + theme.OK.Render("✔ selesai") + "  job " + theme.Chip.Render(jobID) +
					"  → " + filepath.Join(outDir, "report.md"))
				return nil
			}
			if resume != "" {
				return run(target, resume)
			}
			for _, t := range targets {
				if len(targets) > 1 {
					fmt.Println("\n" + theme.Title.Render("=== Target: "+t+" ==="))
				}
				if err := run(t, ""); err != nil {
					return err
				}
			}
			return nil
		},
	}
	c.Flags().StringVarP(&target, "target", "t", "", "URL target, boleh beberapa dipisah koma (harus in-scope)")
	c.Flags().StringVar(&targetsFile, "targets-file", "", "file daftar target (satu URL per baris)")
	c.Flags().StringVar(&scopeFile, "scope-file", "", "file scope (default: host target saja)")
	c.Flags().StringVarP(&outDir, "out", "o", "results", "direktori hasil")
	c.Flags().StringVar(&resume, "resume", "", "lanjutkan job yang ada (job-id)")
	c.Flags().StringVar(&configPath, "config", "", "file konfigurasi YAML (default: ./xyland.yaml bila ada)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "berhenti sebelum eksekusi aktif (FR-09)")
	c.Flags().StringVar(&authA, "auth-a", "", "cookie sesi A untuk auth-differential/IDOR (mis. 'session=...')")
	c.Flags().StringVar(&authB, "auth-b", "", "cookie sesi B untuk auth-differential/IDOR")
	return c
}

func resumeCmd() *cobra.Command {
	var outDir string
	c := &cobra.Command{
		Use:   "resume <job-id>",
		Short: "Lanjutkan job dari checkpoint terakhir di ledger",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// target dibaca dari ledger oleh agent lewat job; untuk resume kita butuh target asli:
			// simpan sederhana: pengguna meneruskan target lewat env XYLAND_TARGET bila perlu.
			target := os.Getenv("XYLAND_TARGET")
			if target == "" {
				return fmt.Errorf("set XYLAND_TARGET=<url target asli> untuk resume (dicatat di report job)")
			}
			root := repoRoot()
			_, err := agent.Run(context.Background(), agent.Options{
				Target: target, OutDir: outDir,
				SkillsDir: filepath.Join(root, "skills"), CVEDir: filepath.Join(root, "knowledge", "cve"),
				ResumeID: args[0], OnEvent: printEvent,
			})
			return err
		},
	}
	c.Flags().StringVarP(&outDir, "out", "o", "results", "direktori hasil (ledger yang sama)")
	return c
}

func skillsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "skills",
		Short: "Daftar skill di library (L1) — yang selalu dilihat agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			idx, err := skills.LoadIndex(filepath.Join(repoRoot(), "skills"))
			if err != nil {
				return err
			}
			fmt.Println(theme.Title.Render(fmt.Sprintf("Skills library — %d skill (indeks v%d)", len(idx.Skills), idx.Version)))
			for _, s := range idx.Skills {
				fmt.Printf("  %s %s %s\n", theme.Chip.Render(s.Name),
					theme.Muted.Render(fmt.Sprintf("L%d · ±%d tok", s.SafetyLevel, s.ContextCost)), s.Description)
			}
			return nil
		},
	}
}

func cveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cve",
		Short: "Daftar kartu CVE terkurasi di knowledge base",
		RunE: func(cmd *cobra.Command, args []string) error {
			cards, err := knowledge.LoadCards(filepath.Join(repoRoot(), "knowledge", "cve"))
			if err != nil {
				return err
			}
			fmt.Println(theme.Title.Render(fmt.Sprintf("Kartu CVE terkurasi — %d", len(cards))))
			for _, c := range cards {
				fmt.Printf("  %s %s\n", theme.Chip.Render(c.ID), theme.Muted.Render(c.Product))
			}
			return nil
		},
	}
}

func flowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "flow",
		Short: "Tampilkan flow state machine xyland (State Brief per state)",
		Run: func(cmd *cobra.Command, args []string) {
			for _, s := range engine.Order {
				b, err := engine.BriefOf(s)
				if err != nil {
					continue
				}
				fmt.Println(theme.Chip.Render(string(s)) + " " + b.Goal)
				fmt.Println(theme.Muted.Render("    aksi sah: " + strings.Join(b.Allowed, ", ") + "  |  gate: " + b.Gate))
			}
		},
	}
}

func tuiCmd() *cobra.Command {
	var outDir string
	c := &cobra.Command{
		Use:   "tui",
		Short: "Dashboard TUI: progres flow, temuan, dan verdict (interaktif di terminal)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return tui.Run(outDir)
		},
	}
	c.Flags().StringVarP(&outDir, "out", "o", "results", "direktori hasil (ledger)")
	return c
}
