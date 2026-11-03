package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseHttpx(t *testing.T) {
	out := "noise line\n{\"url\":\"https://a.lab\",\"status_code\":200,\"title\":\"A\",\"tech\":[\"PHP\",\"WordPress\"]}\n{\"url\":\"https://b.lab\",\"status_code\":301}\n{broken\n"
	res := parseHttpxJSONL(out)
	if len(res) != 2 || res[0].Tech[1] != "WordPress" {
		t.Fatalf("parse httpx salah: %+v", res)
	}
}

func TestParseSubfinder(t *testing.T) {
	res := parseSubfinderLines("a.lab.id\nb.lab.id\na.lab.id\n\n")
	if len(res) != 2 {
		t.Fatalf("subfinder dedup salah: %v", res)
	}
	if !isDomainHost("lab.id") || isDomainHost("127.0.0.1") || isDomainHost("localhost") {
		t.Fatal("isDomainHost salah")
	}
}

func TestParseNuclei(t *testing.T) {
	out := "{\"template-id\":\"t1\",\"matched-at\":\"https://a/x\",\"info\":{\"name\":\"N\",\"severity\":\"high\"}}\nnoise\n"
	res := parseNucleiJSONL(out)
	if len(res) != 1 || res[0].Info.Severity != "high" {
		t.Fatalf("parse nuclei salah: %+v", res)
	}
}

func writeFakeBin(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

const fakeNuclei = "#!/bin/sh\nprev=\"\"; url=\"\"\nfor a in \"$@\"; do if [ \"$prev\" = \"-u\" ]; then url=\"$a\"; fi; prev=\"$a\"; done\nprintf '{\"template-id\":\"fake-tpl\",\"matched-at\":\"%s\",\"info\":{\"name\":\"Fake Finding\",\"severity\":\"high\"}}\\n' \"$url\"\n"
const fakeHttpx = "#!/bin/sh\nprev=\"\"; url=\"\"\nfor a in \"$@\"; do if [ \"$prev\" = \"-u\" ]; then url=\"$a\"; fi; prev=\"$a\"; done\nprintf '{\"url\":\"%s\",\"status_code\":200,\"title\":\"Lab\",\"tech\":[\"PHP\"]}\\n' \"$url\"\n"

func TestRunWithFakeExternalTools(t *testing.T) {
	srv := labServer(t)
	d1 := writeFakeBin(t, "nuclei", fakeNuclei)
	d2 := writeFakeBin(t, "httpx", fakeHttpx)
	t.Setenv("PATH", d1+":"+d2+":"+os.Getenv("PATH"))
	out := t.TempDir()
	jobID, err := Run(context.Background(), Options{Target: srv.URL, OutDir: out, SkillsDir: filepath.Join("..", "..", "skills"), CVEDir: filepath.Join("..", "..", "knowledge", "cve")})
	if err != nil {
		t.Fatal(err)
	}
	st := openStore(t, out)
	fs, _ := st.Findings(jobID)
	found := false
	for _, f := range fs {
		if f.Class == "nuclei" && f.Status == "likely" {
			found = true
		}
	}
	if !found {
		t.Fatalf("finding nuclei (fake) tidak tercatat: %+v", fs)
	}
}

func TestRunIDOR(t *testing.T) {
	srv := labServer(t)
	out := t.TempDir()
	jobID, err := Run(context.Background(), Options{Target: srv.URL, OutDir: out, SkillsDir: filepath.Join("..", "..", "skills"), CVEDir: filepath.Join("..", "..", "knowledge", "cve"), AuthA: "session=alice", AuthB: "session=bob"})
	if err != nil {
		t.Fatal(err)
	}
	st := openStore(t, out)
	fs, _ := st.Findings(jobID)
	found := false
	for _, f := range fs {
		if f.Class == "idor" && f.Status == "confirmed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("IDOR harus confirmed dengan dua sesi: %+v", fs)
	}
}

func TestRunDryRun(t *testing.T) {
	srv := labServer(t)
	out := t.TempDir()
	jobID, err := Run(context.Background(), Options{Target: srv.URL, OutDir: out, SkillsDir: filepath.Join("..", "..", "skills"), CVEDir: filepath.Join("..", "..", "knowledge", "cve"), DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	st := openStore(t, out)
	fs, _ := st.Findings(jobID)
	if len(fs) != 0 {
		t.Fatalf("dry-run tidak boleh menghasilkan finding, dapat %d", len(fs))
	}
	j, _ := st.GetJob(jobID)
	if j.State != "RETRIEVAL" {
		t.Fatalf("dry-run harus berhenti di RETRIEVAL, state=%s", j.State)
	}
}
