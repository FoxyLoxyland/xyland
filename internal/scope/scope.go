// Package scope memuat & menegakkan scope: engine menolak target di luar scope.
package scope

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Scope struct {
	Allow []string // pola host yang diizinkan (boleh "*.example.com")
	Deny  []string
}

func match(pat, host string) bool {
	if strings.HasPrefix(pat, "*.") {
		return strings.HasSuffix(host, pat[1:]) || host == pat[2:]
	}
	return pat == host
}

// Allows memeriksa sebuah URL terhadap scope.
func (s *Scope) Allows(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	for _, d := range s.Deny {
		if match(d, host) {
			return false
		}
	}
	if len(s.Allow) == 0 {
		return false
	}
	for _, a := range s.Allow {
		if match(a, host) {
			return true
		}
	}
	return false
}

// ForTarget membuat scope default dari satu target (host target itu sendiri).
func ForTarget(raw string) (*Scope, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("target tidak valid: %s", raw)
	}
	return &Scope{Allow: []string{u.Hostname()}}, nil
}

// LoadFile membaca scope file: baris "+ host" allow, "- host" deny, "#" komentar.
func LoadFile(path string) (*Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := &Scope{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "+"):
			s.Allow = append(s.Allow, strings.TrimSpace(line[1:]))
		case strings.HasPrefix(line, "-"):
			s.Deny = append(s.Deny, strings.TrimSpace(line[1:]))
		default:
			s.Allow = append(s.Allow, line)
		}
	}
	return s, sc.Err()
}
