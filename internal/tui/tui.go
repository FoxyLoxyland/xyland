// Package tui adalah dashboard terminal xyland (bubbletea + lipgloss).
//
// Layout: header berlogo, strip progres flow (state selesai = mint,
// state aktif = violet berkedip, berikutnya = redup), panel temuan dengan
// warna severity/verdict dari theme, dan footer petunjuk tombol.
// Bila stdout bukan terminal interaktif, tui mencetak snapshot statis
// ber-style yang sama (agar tetap terbaca di log/CI).
package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/FoxyLoxyland/xyland/internal/engine"
	"github.com/FoxyLoxyland/xyland/internal/store"
	"github.com/FoxyLoxyland/xyland/internal/theme"
)

type model struct {
	job      *store.Job
	findings []store.Finding
	assets   []store.Asset
	width    int
}

func loadLatest(outDir string) (*store.Job, []store.Finding, []store.Asset, error) {
	st, err := store.Open(filepath.Join(outDir, "xyland.db"))
	if err != nil {
		return nil, nil, nil, err
	}
	defer st.DB.Close()
	row := st.DB.QueryRow(`SELECT id FROM jobs ORDER BY created_at DESC LIMIT 1`)
	var id string
	if err := row.Scan(&id); err != nil {
		return nil, nil, nil, fmt.Errorf("belum ada job di %s — jalankan 'xyland scan' dulu", outDir)
	}
	job, err := st.GetJob(id)
	if err != nil {
		return nil, nil, nil, err
	}
	fs, _ := st.Findings(id)
	as, _ := st.Assets(id)
	return job, fs, as, nil
}

func Run(outDir string) error {
	job, findings, assets, err := loadLatest(outDir)
	if err != nil {
		return err
	}
	m := model{job: job, findings: findings, assets: assets, width: 96}
	if !isTTY() {
		fmt.Println(m.View())
		return nil
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "esc" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func flowStrip(current string) string {
	cur := engine.Index(engine.State(current))
	var cells []string
	for i, s := range engine.Order {
		label := string(s)
		var st lipgloss.Style
		switch {
		case i < cur:
			st = lipgloss.NewStyle().Foreground(theme.ColorPrimary).Bold(true)
			label = "✔ " + label
		case i == cur:
			st = lipgloss.NewStyle().Foreground(theme.ColorAgent).Bold(true).Underline(true)
			label = "▶ " + label
		default:
			st = theme.Muted
		}
		cells = append(cells, st.Render(label))
	}
	return strings.Join(cells, theme.Muted.Render(" → "))
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString(theme.Banner.Render(theme.Logo) + "\n")
	b.WriteString(theme.Muted.Render("  AI pentest agent — dashboard") + "\n\n")
	if m.job != nil {
		b.WriteString(theme.Chip.Render("JOB "+m.job.ID) + "  " + theme.Title.Render(m.job.Target) + "\n\n")
		b.WriteString(flowStrip(m.job.State) + "\n\n")
	}
	left := theme.Title.Render(fmt.Sprintf("Aset (%d)", len(m.assets))) + "\n"
	for _, a := range m.assets {
		left += fmt.Sprintf("%s %s %s\n", theme.Tool.Render(fmt.Sprintf("%d", a.StatusCode)), a.URL, theme.Muted.Render(a.Title))
	}
	right := theme.Title.Render(fmt.Sprintf("Findings (%d)", len(m.findings))) + "\n"
	for _, f := range m.findings {
		right += fmt.Sprintf("%s %s %s\n",
			theme.Severity(f.Severity).Render(strings.ToUpper(f.Severity)),
			theme.Verdict(f.Status).Render(f.Status), f.Title)
		right += theme.Muted.Render("    "+f.URL) + "\n"
	}
	if len(m.findings) == 0 {
		right += theme.Muted.Render("belum ada finding") + "\n"
	}
	panels := lipgloss.JoinHorizontal(lipgloss.Top,
		theme.Panel.Width(44).Render(left), " ", theme.Panel.Width(48).Render(right))
	b.WriteString(panels + "\n")
	b.WriteString(theme.Muted.Render("\nq / esc — keluar"))
	return b.String()
}
