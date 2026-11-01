// Package theme adalah sumber tunggal styling terminal xyland (CLI & TUI).
//
// Palet "midnight lab": latar gelap, aksen mint neon untuk aksi utama,
// cyan untuk info/tool, violet untuk AI/agent, dan warna severity standar.
// Semua komponen visual WAJIB mengambil warna dari sini agar konsisten.
package theme

import "github.com/charmbracelet/lipgloss"

var (
	ColorPrimary = lipgloss.Color("#3DFFA2") // mint neon — brand & sukses
	ColorAccent  = lipgloss.Color("#39C6F3") // cyan — tool/info
	ColorAgent   = lipgloss.Color("#9B7CFF") // violet — AI/agent
	ColorWarn    = lipgloss.Color("#FFC24B") // amber
	ColorDanger  = lipgloss.Color("#FF5C6C") // merah
	ColorMuted   = lipgloss.Color("#6B7280")
	ColorText    = lipgloss.Color("#E5E7EB")
	ColorPanel   = lipgloss.Color("#1F2430")
	ColorBorder  = lipgloss.Color("#2E3547")
)

var (
	Banner = lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true)
	Title  = lipgloss.NewStyle().Foreground(ColorText).Bold(true)
	Muted  = lipgloss.NewStyle().Foreground(ColorMuted)
	Agent  = lipgloss.NewStyle().Foreground(ColorAgent).Bold(true)
	Tool   = lipgloss.NewStyle().Foreground(ColorAccent)
	OK     = lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true)
	Warn   = lipgloss.NewStyle().Foreground(ColorWarn).Bold(true)
	Danger = lipgloss.NewStyle().Foreground(ColorDanger).Bold(true)

	Panel = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder).
		Padding(0, 1)

	Chip = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#0B0E14")).
		Background(ColorPrimary).
		Bold(true).Padding(0, 1)
)

// Severity mengembalikan style untuk label severity.
func Severity(sev string) lipgloss.Style {
	switch sev {
	case "critical", "high":
		return lipgloss.NewStyle().Foreground(ColorDanger).Bold(true)
	case "medium":
		return lipgloss.NewStyle().Foreground(ColorWarn).Bold(true)
	case "low":
		return lipgloss.NewStyle().Foreground(ColorAccent)
	default:
		return Muted
	}
}

// Verdict mengembalikan style untuk label verdict TP/FP/dll.
func Verdict(v string) lipgloss.Style {
	switch v {
	case "confirmed":
		return OK
	case "likely":
		return Warn
	case "false-positive":
		return Muted
	default:
		return lipgloss.NewStyle().Foreground(ColorWarn)
	}
}

const Logo = `
██╗  ██╗██╗   ██╗██╗      █████╗ ███╗   ██╗██████╗
╚██╗██╔╝╚██╗ ██╔╝██║     ██╔══██╗████╗  ██║██╔══██╗
 ╚███╔╝  ╚████╔╝ ██║     ███████║██╔██╗ ██║██║  ██║
 ██╔██╗   ╚██╔╝  ██║     ██╔══██║██║╚██╗██║██║  ██║
██╔╝ ██╗   ██║   ███████╗██║  ██║██║ ╚████║██████╔╝
╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ `
