// Package validate adalah verdict engine deterministik xyland.
// Verdict TIDAK ditentukan LLM: ia dihitung dari positive test,
// negative control, dan baseline — termasuk anti-200-trap (docs/11, L-2):
// bila baseline (path acak) tidak bisa dibedakan dari respons uji,
// verdict maksimal inconclusive.
package validate

import (
	"context"
	"strings"

	"github.com/FoxyLoxyland/xyland/internal/tools"
)

// Similarity mengembalikan kemiripan kasar dua body (0..1) berbasis
// panjang ternormalisasi + tumpang tindih token sederhana.
func Similarity(a, b string) float64 {
	if a == b {
		return 1
	}
	la, lb := float64(len(a)), float64(len(b))
	if la == 0 && lb == 0 {
		return 1
	}
	if la == 0 || lb == 0 {
		return 0
	}
	lenSim := 1 - abs(la-lb)/max(la, lb)
	ta := tokenSet(a)
	tb := tokenSet(b)
	inter := 0
	for t := range ta {
		if tb[t] {
			inter++
		}
	}
	union := len(ta) + len(tb) - inter
	jac := 0.0
	if union > 0 {
		jac = float64(inter) / float64(union)
	}
	return 0.5*lenSim + 0.5*jac
}

func tokenSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.Fields(strings.ToLower(s)) {
		if len(t) > 2 {
			out[t] = true
		}
	}
	return out
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// FetchBaseline mengambil respons path acak (pasti tidak ada) sebagai baseline anti-200-trap.
func FetchBaseline(ctx context.Context, base string) (*tools.ProbeResult, error) {
	randomPath := "/xyland-baseline-9f3k7-nonexistent"
	return tools.Fetch(ctx, tools.NewClient(), strings.TrimRight(base, "/")+randomPath)
}
