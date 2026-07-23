// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// Package crdt is an op-based sequence CRDT (RGA) over a byte/character stream.
// Concurrent inserts, deletes, and value overwrites from multiple sites merge to
// the same document regardless of the order ops are applied, so it powers
// real-time collaborative text editing without a central coordinator.
package crdt

// ID uniquely identifies an inserted element: a per-site monotonic clock plus the
// site id. The zero ID is the head sentinel.
type ID struct {
	Site  uint64 `json:"s"`
	Clock uint64 `json:"c"`
}

func (a ID) zero() bool { return a.Site == 0 && a.Clock == 0 }

// less is a total order on IDs (clock first, then site) used to order concurrent
// inserts deterministically.
func (a ID) less(b ID) bool {
	if a.Clock != b.Clock {
		return a.Clock < b.Clock
	}
	return a.Site < b.Site
}

// Op is a single mutation. Kind is "ins", "del", or "set".
type Op struct {
	Kind   string `json:"k"`
	ID     ID     `json:"id"`
	Origin ID     `json:"o,omitempty"` // ins: the element inserted after (zero = head)
	Value  byte   `json:"v,omitempty"`
	TS     uint64 `json:"t,omitempty"` // set: value lamport for last-writer-wins
	Site   uint64 `json:"st,omitempty"`
}

type node struct {
	id      ID
	origin  ID
	value   byte
	ts      uint64 // value version, for set LWW
	tsSite  uint64
	deleted bool
}

// Doc is a replicated sequence. It is not safe for concurrent use.
type Doc struct {
	site    uint64
	clock   uint64
	nodes   []node     // document order, including tombstones
	pos     map[ID]int // element id -> index in nodes
	pending []Op       // ops whose dependency has not arrived yet
	lamport uint64     // for set timestamps
}

func New(site uint64) *Doc {
	return &Doc{site: site, pos: map[ID]int{}}
}

func (d *Doc) nextID() ID {
	d.clock++
	return ID{Site: d.site, Clock: d.clock}
}

func (d *Doc) tick(seen uint64) uint64 {
	if seen > d.lamport {
		d.lamport = seen
	}
	d.lamport++
	return d.lamport
}

// visibleIndex maps a position among live (non-deleted) elements to its index in
// nodes; visible==len(live) returns len(nodes) (append at end).
func (d *Doc) nodeIndexForVisible(visible int) int {
	if visible <= 0 {
		return -1 // before the first element (head)
	}
	seen := 0
	for i, n := range d.nodes {
		if n.deleted {
			continue
		}
		seen++
		if seen == visible {
			return i
		}
	}
	return len(d.nodes) - 1
}

func (d *Doc) liveIDAt(visible int) (ID, bool) {
	seen := 0
	for _, n := range d.nodes {
		if n.deleted {
			continue
		}
		if seen == visible {
			return n.id, true
		}
		seen++
	}
	return ID{}, false
}

// InsertAt inserts value so it becomes the element at live position visible,
// returning the op to broadcast.
func (d *Doc) InsertAt(visible int, value byte) Op {
	originIdx := d.nodeIndexForVisible(visible)
	var origin ID
	if originIdx >= 0 {
		origin = d.nodes[originIdx].id
	}
	op := Op{Kind: "ins", ID: d.nextID(), Origin: origin, Value: value}
	d.Apply(op)
	return op
}

// DeleteAt tombstones the element at live position visible.
func (d *Doc) DeleteAt(visible int) (Op, bool) {
	id, ok := d.liveIDAt(visible)
	if !ok {
		return Op{}, false
	}
	op := Op{Kind: "del", ID: id}
	d.Apply(op)
	return op, true
}

// SetAt overwrites the value of the element at live position visible.
func (d *Doc) SetAt(visible int, value byte) (Op, bool) {
	id, ok := d.liveIDAt(visible)
	if !ok {
		return Op{}, false
	}
	op := Op{Kind: "set", ID: id, Value: value, TS: d.tick(d.lamport), Site: d.site}
	d.Apply(op)
	return op, true
}

// Apply integrates a local or remote op, buffering it if its dependency (an
// insert's origin, or the target of del/set) has not arrived yet.
func (d *Doc) Apply(op Op) {
	d.applyOne(op)
	// Retry buffered ops whose dependency may now be satisfied, until quiescent.
	for len(d.pending) > 0 {
		pend := d.pending
		d.pending = nil
		progressed := false
		for _, p := range pend {
			if d.ready(p) {
				d.integrate(p)
				progressed = true
			} else {
				d.pending = append(d.pending, p)
			}
		}
		if !progressed {
			break
		}
	}
}

func (d *Doc) applyOne(op Op) {
	if d.ready(op) {
		d.integrate(op)
	} else {
		d.pending = append(d.pending, op)
	}
}

func (d *Doc) ready(op Op) bool {
	switch op.Kind {
	case "ins":
		if op.Origin.zero() {
			return true
		}
		_, ok := d.pos[op.Origin]
		return ok
	default: // del, set need the target element present
		_, ok := d.pos[op.ID]
		return ok
	}
}

func (d *Doc) integrate(op Op) {
	switch op.Kind {
	case "ins":
		if _, exists := d.pos[op.ID]; exists {
			return // idempotent
		}
		d.tick(op.ID.Clock)
		d.insert(node{id: op.ID, origin: op.Origin, value: op.Value, ts: op.ID.Clock, tsSite: op.ID.Site})
	case "del":
		if i, ok := d.pos[op.ID]; ok {
			d.nodes[i].deleted = true
		}
	case "set":
		if i, ok := d.pos[op.ID]; ok {
			n := &d.nodes[i]
			if op.TS > n.ts || (op.TS == n.ts && op.Site > n.tsSite) {
				n.value = op.Value
				n.ts = op.TS
				n.tsSite = op.Site
			}
			d.tick(op.TS)
		}
	}
}

// insert places n using the RGA rule: among elements sharing an origin, higher
// IDs sort first; descendants stay grouped after their ancestor.
func (d *Doc) insert(n node) {
	originIdx := -1
	if !n.origin.zero() {
		originIdx = d.pos[n.origin]
	}
	i := originIdx + 1
	for i < len(d.nodes) {
		x := d.nodes[i]
		xo := -1
		if !x.origin.zero() {
			xo = d.pos[x.origin]
		}
		if xo < originIdx {
			break // x anchored left of our origin: we belong before it
		}
		if xo == originIdx && n.id.less(x.id) {
			break // sibling with a lower id: we sort before it
		}
		i++
	}
	d.nodes = append(d.nodes, node{})
	copy(d.nodes[i+1:], d.nodes[i:])
	d.nodes[i] = n
	// positions from i onward shifted by one
	for j := i; j < len(d.nodes); j++ {
		d.pos[d.nodes[j].id] = j
	}
}

// Bytes materializes the live document.
func (d *Doc) Bytes() []byte {
	out := make([]byte, 0, len(d.nodes))
	for _, n := range d.nodes {
		if !n.deleted {
			out = append(out, n.value)
		}
	}
	return out
}

// Len is the number of live elements.
func (d *Doc) Len() int {
	n := 0
	for _, e := range d.nodes {
		if !e.deleted {
			n++
		}
	}
	return n
}

// Load seeds a fresh document with initial content as a single site's inserts,
// returning the ops (so a creator can broadcast the starting state).
func (d *Doc) Load(data []byte) []Op {
	ops := make([]Op, 0, len(data))
	for i, b := range data {
		ops = append(ops, d.InsertAt(i, b))
	}
	return ops
}
