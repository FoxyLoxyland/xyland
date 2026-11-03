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
	t.Setenv("XYLAND_BROWSER", "off")
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
	t.Setenv("XYLAND_BROWSER", "off")
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
	t.Setenv("XYLAND_BROWSER", "off")
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

func TestParseKatana(t *testing.T) {
	out := "{\"request\":{\"endpoint\":\"https://a.lab/x?id=1\"}}\n{\"url\":\"https://a.lab/y?q=2\"}\nnoise\n{\"request\":{\"endpoint\":\"https://a.lab/x?id=1\"}}\n"
	res := parseKatanaJSONL(out)
	if len(res) != 2 {
		t.Fatalf("parse katana salah: %v", res)
	}
}

const fakeKatana = "#!/bin/sh\nprev=\"\"; url=\"\"\nfor a in \"$@\"; do if [ \"$prev\" = \"-u\" ]; then url=\"$a\"; fi; prev=\"$a\"; done\nprintf '{\"request\":{\"endpoint\":\"%s/deep?token=abc\"}}\\n' \"$url\"\n"

func TestRunWithFakeKatana(t *testing.T) {
	t.Setenv("XYLAND_BROWSER", "off")
	srv := labServer(t)
	d := writeFakeBin(t, "katana", fakeKatana)
	t.Setenv("PATH", d+":"+os.Getenv("PATH"))
	out := t.TempDir()
	// endpoint /deep tidak ada di lab (SPA fallback) — yang diverifikasi: katana dipanggil & tercatat sebagai receipt
	jobID, err := Run(context.Background(), Options{Target: srv.URL, OutDir: out, SkillsDir: filepath.Join("..", "..", "skills"), CVEDir: filepath.Join("..", "..", "knowledge", "cve")})
	if err != nil {
		t.Fatal(err)
	}
	st := openStore(t, out)
	rows, err := st.DB.Query(`SELECT COUNT(*) FROM executions WHERE job_id=? AND tool='katana'`, jobID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	rows.Next()
	var n int
	_ = rows.Scan(&n)
	if n != 1 {
		t.Fatalf("receipt katana harus 1, dapat %d", n)
	}
}

func TestParseFFUF(t *testing.T) {
	out := `{"results":[{"url":"https://a.lab/admin","status":200,"length":55},{"url":"https://a.lab/api","status":401,"length":9}]}`
	res := parseFFUFJSON(out)
	if len(res) != 2 || res[0].Status != 200 {
		t.Fatalf("parse ffuf salah: %+v", res)
	}
}

const fakeFFUF = "#!/bin/sh\nprintf '{\"results\":[{\"url\":\"https://unused.lab/admin\",\"status\":200,\"length\":10}]}\n'\n"

func TestRunWithFakeFFUF(t *testing.T) {
	t.Setenv("XYLAND_BROWSER", "off")
	srv := labServer(t)
	d := writeFakeBin(t, "ffuf", fakeFFUF)
	t.Setenv("PATH", d+":"+os.Getenv("PATH"))
	out := t.TempDir()
	jobID, err := Run(context.Background(), Options{Target: srv.URL, OutDir: out, SkillsDir: filepath.Join("..", "..", "skills"), CVEDir: filepath.Join("..", "..", "knowledge", "cve")})
	if err != nil {
		t.Fatal(err)
	}
	st := openStore(t, out)
	rows, _ := st.DB.Query(`SELECT COUNT(*) FROM executions WHERE job_id=? AND tool='ffuf'`, jobID)
	defer rows.Close()
	rows.Next()
	var n int
	_ = rows.Scan(&n)
	if n != 1 {
		t.Fatalf("receipt ffuf harus 1, dapat %d", n)
	}
}
