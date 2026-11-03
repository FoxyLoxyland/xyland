package skills

import (
	"path/filepath"
	"testing"
)

// memakai library asli repo (relatif dari paket ini: ../../skills)
func repoSkillsDir() string { return filepath.Join("..", "..", "skills") }

func TestLoadRealIndex(t *testing.T) {
	idx, err := LoadIndex(repoSkillsDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Skills) < 22 {
		t.Fatalf("library harus >=22 skill, dapat %d", len(idx.Skills))
	}
}

func TestSelectRespectsMaxAndRelevance(t *testing.T) {
	idx, err := LoadIndex(repoSkillsDir())
	if err != nil {
		t.Fatal(err)
	}
	sel := idx.Select([]string{"param-reflection"}, "", 5)
	if len(sel) == 0 || len(sel) > 5 {
		t.Fatalf("seleksi salah: %d skill", len(sel))
	}
	found := false
	for _, s := range sel {
		if s.Name == "xss-reflected" {
			found = true
		}
	}
	if !found {
		t.Fatal("tag param-reflection harus memilih xss-reflected")
	}
	none := idx.Select([]string{"teknologi-yang-tidak-ada-xyz"}, "", 5)
	if len(none) != 0 {
		t.Fatalf("tag tak dikenal harus menghasilkan 0, dapat %d", len(none))
	}
}
