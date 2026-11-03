package agent

import (
	"path/filepath"
	"testing"

	"github.com/FoxyLoxyland/xyland/internal/store"
)

func openStore(t *testing.T, outDir string) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(outDir, "xyland.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	return st
}
