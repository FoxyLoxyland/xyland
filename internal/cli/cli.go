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
	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/knowledge"
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
	var target, scopeFile, outDir, resume string
	c := &cobra.Command{
		Use:   "scan",
		Short: "Jalankan flow penuh: scope → recon → hipotesis → eksekusi → verdict → PoC → report",
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" && resume == "" {
				return fmt.Errorf("wajib: -t/--target (atau --resume <job-id>)")
			}
			fmt.Println(theme.Banner.Render(theme.Logo))
			fmt.Println(theme.Muted.Render("  AI pentest agent — no exploit, no report"))
			root := repoRoot()
			jobID, err := agent.Run(context.Background(), agent.Options{
				Target: target, ScopeFile: scopeFile, OutDir: outDir,
				SkillsDir: filepath.Join(root, "skills"), CVEDir: filepath.Join(root, "knowledge", "cve"),
				ResumeID: resume, OnEvent: printEvent,
			})
			if err != nil {
				return err
			}
			fmt.Println("\n" + theme.OK.Render("✔ selesai") + "  job " + theme.Chip.Render(jobID) +
				"  → " + filepath.Join(outDir, "report.md"))
			return nil
		},
	}
	c.Flags().StringVarP(&target, "target", "t", "", "URL target (harus in-scope)")
	c.Flags().StringVar(&scopeFile, "scope-file", "", "file scope (default: host target saja)")
	c.Flags().StringVarP(&outDir, "out", "o", "results", "direktori hasil")
	c.Flags().StringVar(&resume, "resume", "", "lanjutkan job yang ada (job-id)")
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
