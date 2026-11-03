package scope

import "testing"

func TestAllowsDenyWildcard(t *testing.T) {
	s := &Scope{Allow: []string{"example.com", "*.lab.id"}, Deny: []string{"admin.example.com"}}
	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com/x", true},
		{"https://sub.lab.id/", true},
		{"https://lab.id/", true},
		{"https://admin.example.com/", false}, // deny menang
		{"https://other.com/", false},
		{"bukan-url", false},
	}
	for _, c := range cases {
		if got := s.Allows(c.url); got != c.want {
			t.Errorf("Allows(%q)=%v, mau %v", c.url, got, c.want)
		}
	}
}

func TestForTarget(t *testing.T) {
	s, err := ForTarget("http://127.0.0.1:8099/path")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Allows("http://127.0.0.1:9999/other") {
		t.Error("host sama (port beda) harus in-scope")
	}
	if s.Allows("http://127.0.0.2/") {
		t.Error("host beda harus di luar scope")
	}
}
