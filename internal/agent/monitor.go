package agent

import (
	"strings"

	"github.com/FoxyLoxyland/xyland/internal/store"
)

func findingKey(f store.Finding) string {
	return f.Class + "|" + strings.TrimRight(f.URL, "/")
}

func reportable(f store.Finding) bool {
	return f.Status == "confirmed" || f.Status == "likely"
}

// DiffFindings membandingkan dua daftar finding (yang reportable saja):
// newF = muncul di curr tapi tidak di prev; resolvedF = ada di prev tapi hilang di curr.
func DiffFindings(prev, curr []store.Finding) (newF, resolvedF []store.Finding) {
	prevKeys := map[string]store.Finding{}
	for _, f := range prev {
		if reportable(f) {
			prevKeys[findingKey(f)] = f
		}
	}
	currKeys := map[string]store.Finding{}
	for _, f := range curr {
		if reportable(f) {
			currKeys[findingKey(f)] = f
		}
	}
	for k, f := range currKeys {
		if _, ok := prevKeys[k]; !ok {
			newF = append(newF, f)
		}
	}
	for k, f := range prevKeys {
		if _, ok := currKeys[k]; !ok {
			resolvedF = append(resolvedF, f)
		}
	}
	return newF, resolvedF
}
