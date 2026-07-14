package crdt

import (
	"math/rand"
	"testing"
)

func TestBasicOps(t *testing.T) {
	d := New(1)
	d.Load([]byte("hello"))
	if got := string(d.Bytes()); got != "hello" {
		t.Fatalf("load = %q", got)
	}
	d.DeleteAt(1) // remove 'e'
	if got := string(d.Bytes()); got != "hllo" {
		t.Fatalf("delete = %q", got)
	}
	d.SetAt(0, 'H') // overwrite 'h' -> 'H'
	if got := string(d.Bytes()); got != "Hllo" {
		t.Fatalf("set = %q", got)
	}
	d.InsertAt(d.Len(), '!')
	if got := string(d.Bytes()); got != "Hllo!" {
		t.Fatalf("append = %q", got)
	}
}

// Two sites inserting at the same position converge to the same order.
func TestConcurrentInsertConverges(t *testing.T) {
	a, b := New(1), New(2)
	for _, op := range a.Load([]byte("abc")) {
		b.Apply(op)
	}
	opA := a.InsertAt(0, 'X')
	opB := b.InsertAt(0, 'Y')
	b.Apply(opA)
	a.Apply(opB)
	if string(a.Bytes()) != string(b.Bytes()) {
		t.Fatalf("diverged: %q vs %q", a.Bytes(), b.Bytes())
	}
}

// Out-of-order delivery (op arrives before its dependency) still converges.
func TestBufferingOutOfOrder(t *testing.T) {
	src := New(1)
	ops := src.Load([]byte("abc"))
	del, _ := src.DeleteAt(1)

	dst := New(2)
	dst.Apply(del)    // delete before its target insert exists -> buffered
	dst.Apply(ops[2]) // 'c'
	dst.Apply(ops[0]) // 'a'
	dst.Apply(ops[1]) // 'b' -> now the delete can resolve
	if got := string(dst.Bytes()); got != "ac" {
		t.Fatalf("out-of-order = %q", got)
	}
	if len(dst.pending) != 0 {
		t.Fatalf("unresolved pending: %d", len(dst.pending))
	}
}

// Three sites edit in sync; replaying every op into a fresh doc in shuffled order
// must reach the same document (RGA + LWW are order-independent given deps).
func TestConvergenceShuffled(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	sites := []*Doc{New(1), New(2), New(3)}
	var log []Op
	seed := func(op Op, from int) {
		log = append(log, op)
		for i, s := range sites {
			if i != from {
				s.Apply(op)
			}
		}
	}
	for _, op := range sites[0].Load([]byte("hello world")) {
		seed(op, 0)
	}
	for step := 0; step < 200; step++ {
		si := rnd.Intn(len(sites))
		s := sites[si]
		n := s.Len()
		switch rnd.Intn(3) {
		case 0:
			seed(s.InsertAt(rnd.Intn(n+1), byte('a'+rnd.Intn(26))), si)
		case 1:
			if n > 1 {
				if op, ok := s.DeleteAt(rnd.Intn(n)); ok {
					seed(op, si)
				}
			}
		case 2:
			if n > 0 {
				if op, ok := s.SetAt(rnd.Intn(n), byte('A'+rnd.Intn(26))); ok {
					seed(op, si)
				}
			}
		}
	}
	want := string(sites[0].Bytes())
	for i, s := range sites[1:] {
		if string(s.Bytes()) != want {
			t.Fatalf("site %d diverged from site 0: %q vs %q", i+1, s.Bytes(), want)
		}
	}
	shuf := append([]Op(nil), log...)
	rnd.Shuffle(len(shuf), func(i, j int) { shuf[i], shuf[j] = shuf[j], shuf[i] })
	fresh := New(99)
	for _, op := range shuf {
		fresh.Apply(op)
	}
	if len(fresh.pending) != 0 {
		t.Fatalf("fresh replay left %d unresolved ops", len(fresh.pending))
	}
	if got := string(fresh.Bytes()); got != want {
		t.Fatalf("shuffled replay diverged:\n got  %q\n want %q", got, want)
	}
}
