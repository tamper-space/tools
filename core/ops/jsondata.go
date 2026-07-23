// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// Structured-data operations (tranche 8 toward CyberChef parity): JSON
// beautify/minify and CSV to JSON. Standard-library only.
package ops

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
)

func init() {
	reg(Op{ID: "json-beautify", Name: "JSON Beautify", Category: "Text", Params: []Param{
		{Name: "spaces", Label: "Indent spaces", Type: ParamNumber, Default: "2"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		n := a.Int("spaces", 2)
		if n < 0 {
			n = 0
		}
		var out bytes.Buffer
		if err := json.Indent(&out, bytes.TrimSpace(in), "", strings.Repeat(" ", n)); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		return out.Bytes(), nil
	}})
	reg(Op{ID: "json-minify", Name: "JSON Minify", Category: "Text", run: func(in []byte, a Args) ([]byte, error) {
		var out bytes.Buffer
		if err := json.Compact(&out, bytes.TrimSpace(in)); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		return out.Bytes(), nil
	}})
	reg(Op{ID: "csv-to-json", Name: "CSV to JSON", Category: "Text", run: csvToJSON})
}

// csvToJSON reads CSV (first row = headers) into a JSON array of objects,
// preserving column order (built by hand, since a Go map would sort the keys).
func csvToJSON(in []byte, a Args) ([]byte, error) {
	r := csv.NewReader(bytes.NewReader(in))
	r.FieldsPerRecord = -1 // tolerate ragged rows
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("CSV: %w", err)
	}
	if len(records) == 0 {
		return []byte("[]"), nil
	}
	headers := records[0]
	var raw bytes.Buffer
	raw.WriteByte('[')
	for ri, rec := range records[1:] {
		if ri > 0 {
			raw.WriteByte(',')
		}
		raw.WriteByte('{')
		for i, h := range headers {
			if i > 0 {
				raw.WriteByte(',')
			}
			val := ""
			if i < len(rec) {
				val = rec[i]
			}
			hj, _ := json.Marshal(h)
			vj, _ := json.Marshal(val)
			raw.Write(hj)
			raw.WriteByte(':')
			raw.Write(vj)
		}
		raw.WriteByte('}')
	}
	raw.WriteByte(']')
	var pretty bytes.Buffer
	if json.Indent(&pretty, raw.Bytes(), "", "  ") != nil {
		return raw.Bytes(), nil
	}
	return pretty.Bytes(), nil
}
