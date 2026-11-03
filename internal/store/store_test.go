package store

import (
	"path/filepath"
	"testing"
)

func TestJobAssetFindingRoundtrip(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	if err := st.CreateJob("job-t", "http://lab.local"); err != nil {
		t.Fatal(err)
	}
	execID, err := st.RecordExecution("job-t", "prober", "http://lab.local", 0, "ok")
	if err != nil || execID == 0 {
		t.Fatalf("receipt gagal: %v id=%d", err, execID)
	}
	if _, err := st.AddAsset(Asset{JobID: "job-t", URL: "http://lab.local", StatusCode: 200, Title: "Lab", ExecutionID: execID}); err != nil {
		t.Fatal(err)
	}
	fid, err := st.AddFinding(Finding{JobID: "job-t", Class: "exposure", Title: "Exposed", URL: "http://lab.local/.git/config", Severity: "high", Status: "confirmed", Evidence: "marker", ExecutionID: execID})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateFindingStatus(fid, "confirmed", "/tmp/poc.py"); err != nil {
		t.Fatal(err)
	}
	fs, err := st.Findings("job-t")
	if err != nil || len(fs) != 1 || fs[0].PocPath != "/tmp/poc.py" || fs[0].ExecutionID != execID {
		t.Fatalf("finding roundtrip salah: %+v err=%v", fs, err)
	}
	if err := st.SetState("job-t", "DONE"); err != nil {
		t.Fatal(err)
	}
	j, err := st.GetJob("job-t")
	if err != nil || j.State != "DONE" {
		t.Fatalf("job state salah: %+v %v", j, err)
	}
}
