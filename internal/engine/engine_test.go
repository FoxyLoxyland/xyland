package engine

import "testing"

func TestFlowOrderAndBriefs(t *testing.T) {
	if len(Order) != 10 {
		t.Fatalf("flow harus 9 state + DONE, dapat %d", len(Order))
	}
	for _, s := range Order {
		if s == StateDone {
			continue
		}
		b, err := BriefOf(s)
		if err != nil {
			t.Fatalf("state %s tanpa State Brief: %v", s, err)
		}
		if b.Goal == "" || b.Gate == "" || len(b.Allowed) == 0 {
			t.Fatalf("State Brief %s tidak lengkap", s)
		}
	}
}

func TestTransitions(t *testing.T) {
	cur := StateScope
	for cur != StateDone {
		nxt, err := Next(cur)
		if err != nil {
			t.Fatalf("transisi dari %s gagal: %v", cur, err)
		}
		if Index(nxt) != Index(cur)+1 {
			t.Fatalf("transisi %s -> %s tidak berurutan", cur, nxt)
		}
		cur = nxt
	}
	if _, err := Next(StateDone); err == nil {
		t.Fatal("DONE tidak boleh punya transisi keluar")
	}
}
