package agent

import (
	"testing"

	"github.com/FoxyLoxyland/xyland/internal/store"
)

func TestDiffFindings(t *testing.T) {
	prev := []store.Finding{
		{Class: "sqli", URL: "http://x/a?id=1", Status: "confirmed"},
		{Class: "cors", URL: "http://x", Status: "likely"},
		{Class: "exposure", URL: "http://x/.env", Status: "false-positive"}, // tidak reportable
	}
	curr := []store.Finding{
		{Class: "sqli", URL: "http://x/a?id=1/", Status: "confirmed"}, // sama (normalisasi /)
		{Class: "idor", URL: "http://x/p?id=2", Status: "confirmed"},  // baru
	}
	newF, resF := DiffFindings(prev, curr)
	if len(newF) != 1 || newF[0].Class != "idor" {
		t.Fatalf("finding baru salah: %+v", newF)
	}
	if len(resF) != 1 || resF[0].Class != "cors" {
		t.Fatalf("resolved salah: %+v", resF)
	}
}
