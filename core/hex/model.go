// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package hex

import "fmt"

// Event describes a model mutation, delivered to the subscriber after it applied.
type Event struct {
	Type   string // "bytes", "cursor", "selection"
	Offset int    // first affected byte for "bytes" events
	Length int    // affected length for "bytes" events (post-mutation)
}

// Model is a hex editing session: the buffer plus cursor and selection. It is
// the engine's entire state; presentation, history, and collaboration belong to
// the host (snapshot in, events out). Mutations are strict (out-of-range writes
// error), cursor and selection are clamped, and every applied change emits one
// Event.
type Model struct {
	data     []byte
	cursor   int
	selStart int // -1 when nothing is selected
	selEnd   int // exclusive
	notify   func(Event)
}

func NewModel() *Model { return &Model{selStart: -1, selEnd: -1} }

// OnEvent registers the single event sink (the WASM shim fans out to JS
// subscribers). Passing nil disables delivery.
func (m *Model) OnEvent(fn func(Event)) { m.notify = fn }

func (m *Model) emit(e Event) {
	if m.notify != nil {
		m.notify(e)
	}
}

// Load replaces the buffer with a copy of data and resets cursor and selection.
func (m *Model) Load(data []byte) {
	m.data = append([]byte(nil), data...)
	m.cursor = 0
	m.selStart, m.selEnd = -1, -1
	m.emit(Event{Type: "bytes", Offset: 0, Length: len(m.data)})
}

// Bytes returns a copy of the buffer.
func (m *Model) Bytes() []byte { return append([]byte(nil), m.data...) }

func (m *Model) Len() int { return len(m.data) }

func (m *Model) Cursor() int { return m.cursor }

// SetCursor moves the cursor, clamped to [0, Len].
func (m *Model) SetCursor(n int) {
	m.cursor = clamp(n, 0, len(m.data))
	m.emit(Event{Type: "cursor"})
}

// Selection returns the selected half-open range, or ok=false when none.
func (m *Model) Selection() (start, end int, ok bool) {
	if m.selStart < 0 {
		return 0, 0, false
	}
	return m.selStart, m.selEnd, true
}

// Select sets the selection to the half-open range [a, b), normalizing order
// and clamping to the buffer. An empty range clears the selection.
func (m *Model) Select(a, b int) {
	if a > b {
		a, b = b, a
	}
	a, b = clamp(a, 0, len(m.data)), clamp(b, 0, len(m.data))
	if a == b {
		m.ClearSelection()
		return
	}
	m.selStart, m.selEnd = a, b
	m.emit(Event{Type: "selection"})
}

func (m *Model) ClearSelection() {
	if m.selStart < 0 {
		return
	}
	m.selStart, m.selEnd = -1, -1
	m.emit(Event{Type: "selection"})
}

// Insert places b at offset (0..Len). Cursor and selection past the insertion
// point shift right.
func (m *Model) Insert(offset int, b []byte) error {
	if offset < 0 || offset > len(m.data) {
		return fmt.Errorf("hex: insert at %d outside 0..%d", offset, len(m.data))
	}
	if len(b) == 0 {
		return nil
	}
	m.data = append(m.data[:offset], append(append([]byte(nil), b...), m.data[offset:]...)...)
	if m.cursor >= offset {
		m.cursor += len(b)
	}
	m.shiftSelection(offset, len(b))
	m.emit(Event{Type: "bytes", Offset: offset, Length: len(b)})
	return nil
}

// Delete removes n bytes at offset. Cursor and selection collapse toward the cut.
func (m *Model) Delete(offset, n int) error {
	if n < 0 || offset < 0 || offset+n > len(m.data) {
		return fmt.Errorf("hex: delete %d at %d outside 0..%d", n, offset, len(m.data))
	}
	if n == 0 {
		return nil
	}
	m.data = append(m.data[:offset], m.data[offset+n:]...)
	m.cursor = collapse(m.cursor, offset, n)
	if m.selStart >= 0 {
		s, e := collapse(m.selStart, offset, n), collapse(m.selEnd, offset, n)
		if s == e {
			m.selStart, m.selEnd = -1, -1
		} else {
			m.selStart, m.selEnd = s, e
		}
	}
	m.emit(Event{Type: "bytes", Offset: offset, Length: 0})
	return nil
}

// Overwrite replaces bytes in place; the range must already exist.
func (m *Model) Overwrite(offset int, b []byte) error {
	if offset < 0 || offset+len(b) > len(m.data) {
		return fmt.Errorf("hex: overwrite %d at %d outside 0..%d", len(b), offset, len(m.data))
	}
	if len(b) == 0 {
		return nil
	}
	copy(m.data[offset:], b)
	m.emit(Event{Type: "bytes", Offset: offset, Length: len(b)})
	return nil
}

func (m *Model) shiftSelection(offset, n int) {
	if m.selStart < 0 {
		return
	}
	if m.selStart >= offset {
		m.selStart += n
	}
	if m.selEnd > offset {
		m.selEnd += n
	}
}

func clamp(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// collapse maps a position through a deletion of n bytes at offset.
func collapse(pos, offset, n int) int {
	switch {
	case pos <= offset:
		return pos
	case pos >= offset+n:
		return pos - n
	default:
		return offset
	}
}
