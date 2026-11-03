package poc

import (
	"strings"
	"testing"
)

func TestGenerateAllClasses(t *testing.T) {
	for _, class := range []string{"exposure", "xss-reflected", "open-redirect", "sqli", "path-traversal", "cors", "idor"} {
		content, ok := Generate(class, "http://lab.local/x?a=1")
		if !ok {
			t.Fatalf("kelas %s harus punya generator PoC", class)
		}
		if !strings.Contains(content, "#!/usr/bin/env python3") || !strings.Contains(content, "VERDICT") {
			t.Fatalf("PoC %s tidak memenuhi kontrak self-verifying", class)
		}
		if strings.Contains(content, "DROP TABLE") || strings.Contains(content, "UNION SELECT") {
			t.Fatalf("PoC %s mengandung payload ekstraksi/destruktif — dilarang", class)
		}
	}
	if _, ok := Generate("kelas-ngawur", "http://lab.local"); ok {
		t.Fatal("kelas tak dikenal tidak boleh menghasilkan PoC")
	}
}
