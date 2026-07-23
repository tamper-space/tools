// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package hex

import (
	"bytes"
	"testing"
)

func collect(m *Model) *[]Event {
	var evs []Event
	m.OnEvent(func(e Event) { evs = append(evs, e) })
	return &evs
}

func TestModelLoadAndSnapshot(t *testing.T) {
	m := NewModel()
	evs := collect(m)
	m.Load([]byte{1, 2, 3})
	if m.Len() != 3 || m.Cursor() != 0 {
		t.Fatalf("len=%d cursor=%d", m.Len(), m.Cursor())
	}
	b := m.Bytes()
	b[0] = 99
	if m.Bytes()[0] != 1 {
		t.Fatal("Bytes must return a copy")
	}
	if len(*evs) != 1 || (*evs)[0].Type != "bytes" || (*evs)[0].Length != 3 {
		t.Fatalf("events: %+v", *evs)
	}
}

func TestModelEditOps(t *testing.T) {
	m := NewModel()
	m.Load([]byte{0xaa, 0xbb, 0xcc})
	if err := m.Insert(1, []byte{0x11, 0x22}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Bytes(), []byte{0xaa, 0x11, 0x22, 0xbb, 0xcc}) {
		t.Fatalf("after insert: %x", m.Bytes())
	}
	if err := m.Overwrite(0, []byte{0xff}); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(1, 2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Bytes(), []byte{0xff, 0xbb, 0xcc}) {
		t.Fatalf("after delete: %x", m.Bytes())
	}
	if err := m.Insert(99, []byte{1}); err == nil {
		t.Fatal("out-of-range insert must error")
	}
	if err := m.Overwrite(2, []byte{1, 2}); err == nil {
		t.Fatal("out-of-range overwrite must error")
	}
	if err := m.Delete(0, 4); err == nil {
		t.Fatal("out-of-range delete must error")
	}
}

func TestModelCursorAndSelectionTracking(t *testing.T) {
	m := NewModel()
	m.Load(make([]byte, 10))
	m.SetCursor(5)
	m.Select(2, 8)

	// Insert before both: everything shifts right.
	if err := m.Insert(0, []byte{1, 1}); err != nil {
		t.Fatal(err)
	}
	if m.Cursor() != 7 {
		t.Fatalf("cursor after insert: %d", m.Cursor())
	}
	if s, e, ok := m.Selection(); !ok || s != 4 || e != 10 {
		t.Fatalf("selection after insert: %d..%d ok=%v", s, e, ok)
	}

	// Delete a range spanning the selection start: positions collapse to the cut.
	if err := m.Delete(2, 4); err != nil {
		t.Fatal(err)
	}
	if m.Cursor() != 3 {
		t.Fatalf("cursor after delete: %d", m.Cursor())
	}
	if s, e, ok := m.Selection(); !ok || s != 2 || e != 6 {
		t.Fatalf("selection after delete: %d..%d ok=%v", s, e, ok)
	}

	// Deleting the whole selected range clears the selection.
	m.Select(1, 3)
	if err := m.Delete(1, 2); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := m.Selection(); ok {
		t.Fatal("selection should clear when its range is deleted")
	}
}

func TestModelSelectNormalizesAndClamps(t *testing.T) {
	m := NewModel()
	m.Load(make([]byte, 4))
	m.Select(9, 2)
	if s, e, ok := m.Selection(); !ok || s != 2 || e != 4 {
		t.Fatalf("normalized selection: %d..%d ok=%v", s, e, ok)
	}
	m.Select(3, 3)
	if _, _, ok := m.Selection(); ok {
		t.Fatal("empty range must clear selection")
	}
	m.SetCursor(-5)
	if m.Cursor() != 0 {
		t.Fatal("cursor must clamp low")
	}
	m.SetCursor(99)
	if m.Cursor() != 4 {
		t.Fatal("cursor must clamp high")
	}
}
