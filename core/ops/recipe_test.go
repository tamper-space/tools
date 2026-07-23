// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package ops

import "testing"

func steps(ss ...Step) []Step { return ss }
func step(id string, kv ...string) Step {
	a := Args{}
	for i := 0; i+1 < len(kv); i += 2 {
		a[kv[i]] = kv[i+1]
	}
	return Step{ID: id, Args: a}
}

func TestRunRecipeLinear(t *testing.T) {
	// base64 then uppercase, plain linear chain.
	r := RunRecipe(steps(step("to-base64"), step("to-upper")), []byte("hi"))
	if r.FailedAt != -1 || string(r.Output) != "AGK=" { // base64("hi")="aGk=" -> upper
		t.Fatalf("linear = %q failedAt=%d", r.Output, r.FailedAt)
	}
}

func TestRunRecipeForkMerge(t *testing.T) {
	// Fork on newline, uppercase each branch, merge back.
	r := RunRecipe(steps(
		step("fork", "splitDelim", "Line feed", "mergeDelim", "Line feed"),
		step("to-upper"),
		step("merge"),
	), []byte("a\nb\nc"))
	if string(r.Output) != "A\nB\nC" {
		t.Fatalf("fork/merge = %q", r.Output)
	}

	// Fork with a different merge delimiter, left unmerged: output joins on it.
	r = RunRecipe(steps(
		step("fork", "splitDelim", "Comma", "mergeDelim", " | "),
		step("to-upper"),
	), []byte("a,b,c"))
	if string(r.Output) != "A | B | C" {
		t.Fatalf("fork unmerged = %q", r.Output)
	}
}

func TestRunRecipeRegister(t *testing.T) {
	// Capture a value, then reference it via $R0 in a later step's argument.
	r := RunRecipe(steps(
		step("register", "regex", `key=(\w+)`),
		step("find-replace", "find", "PLACEHOLDER", "replace", "$R0"),
	), []byte("key=s3cret PLACEHOLDER"))
	if string(r.Output) != "key=s3cret s3cret" {
		t.Fatalf("register = %q", r.Output)
	}
}

func TestRunRecipeErrorAndDisabled(t *testing.T) {
	// A failing op stops the run and records the index + error.
	r := RunRecipe(steps(step("to-upper"), step("from-base64"), step("to-lower")), []byte("not valid base64!!"))
	if r.FailedAt != 1 || r.Error == "" || r.Steps[1].Error == "" {
		t.Fatalf("expected failure at step 1, got failedAt=%d err=%q", r.FailedAt, r.Error)
	}

	// A disabled step is skipped (the invalid from-base64 is disabled).
	r = RunRecipe([]Step{
		{ID: "to-upper"},
		{ID: "from-base64", Disabled: true},
		{ID: "to-lower"},
	}, []byte("Hello"))
	if r.FailedAt != -1 || string(r.Output) != "hello" {
		t.Fatalf("disabled skip = %q failedAt=%d", r.Output, r.FailedAt)
	}
}

func TestFlowOpsErrorStandalone(t *testing.T) {
	// The control ops must refuse a direct Run (they exist only for the interpreter).
	for _, id := range []string{"fork", "merge", "register", "subsection", "label", "jump", "conditional-jump"} {
		if _, err := Run(id, []byte("x"), nil); err == nil {
			t.Errorf("%s should error when run standalone", id)
		}
	}
}

func TestRunRecipeSubsection(t *testing.T) {
	// Uppercase only the letter runs; digits and spaces untouched.
	r := RunRecipe(steps(
		step("subsection", "regex", `[a-z]+`),
		step("to-upper"),
	), []byte("foo 123 bar"))
	if string(r.Output) != "FOO 123 BAR" {
		t.Fatalf("subsection = %q", r.Output)
	}
	// Merge ends the subsection: the following op applies to the whole data.
	r = RunRecipe(steps(
		step("subsection", "regex", `[a-z]+`),
		step("to-upper"),
		step("merge"),
		step("reverse"),
	), []byte("ab 12"))
	if string(r.Output) != "21 BA" {
		t.Fatalf("subsection+merge+reverse = %q", r.Output)
	}
}

func TestRunRecipeJumpLoop(t *testing.T) {
	// Loop: collapse doubled 'a's until none remain (conditional jump back to label).
	r := RunRecipe(steps(
		step("label", "name", "L"),
		step("find-replace", "find", "aa", "replace", "a"),
		step("conditional-jump", "regex", "aa", "label", "L", "maxJumps", "10"),
	), []byte("aaaaaaaa"))
	if r.FailedAt != -1 || string(r.Output) != "a" {
		t.Fatalf("jump loop = %q failedAt=%d", r.Output, r.FailedAt)
	}

	// An unconditional jump is bounded by maxJumps (no hang, no iterCap failure).
	r = RunRecipe(steps(
		step("label", "name", "L"),
		step("jump", "label", "L", "maxJumps", "3"),
	), []byte("x"))
	if r.FailedAt != -1 || string(r.Output) != "x" {
		t.Fatalf("bounded jump = %q failedAt=%d", r.Output, r.FailedAt)
	}
}
