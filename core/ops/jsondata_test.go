// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package ops

import "testing"

func TestJSONData(t *testing.T) {
	// Minify then beautify is a stable round trip of structure.
	min := mustRun(t, "json-minify", "{ \"b\": 1,  \"a\":[1, 2 ] }", nil)
	if min != `{"b":1,"a":[1,2]}` {
		t.Fatalf("json-minify = %q", min)
	}
	beauty := mustRun(t, "json-beautify", min, Args{"spaces": "2"})
	if beauty != "{\n  \"b\": 1,\n  \"a\": [\n    1,\n    2\n  ]\n}" {
		t.Fatalf("json-beautify = %q", beauty)
	}
	if _, err := Run("json-minify", []byte("{bad"), nil); err == nil {
		t.Error("json-minify should reject invalid JSON")
	}

	// CSV to JSON preserves column order and handles quoted commas.
	csv := "name,age,city\n\"Doe, John\",42,NYC\nJane,30,LA"
	got := mustRun(t, "csv-to-json", csv, nil)
	want := "[\n  {\n    \"name\": \"Doe, John\",\n    \"age\": \"42\",\n    \"city\": \"NYC\"\n  },\n  {\n    \"name\": \"Jane\",\n    \"age\": \"30\",\n    \"city\": \"LA\"\n  }\n]"
	if got != want {
		t.Fatalf("csv-to-json =\n%s\nwant\n%s", got, want)
	}
}
