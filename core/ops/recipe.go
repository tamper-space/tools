// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// Recipe interpreter (tranche 5 toward CyberChef parity): runs a list of steps
// with flow control. Fork splits the data into branches that later steps apply to
// independently; Merge recombines them; Register captures regex groups into $R0..
// referenced in later step arguments. This is the engine's recipe runner, exposed
// on the API as runRecipe so hosts (the workbench first) drive the whole chain
// through one call instead of looping op-by-op.
package ops

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// Step is one recipe entry. Args values are strings (parsed per param type by the
// op). Disabled steps are skipped, preserving their slot in the result.
type Step struct {
	ID       string `json:"id"`
	Args     Args   `json:"args"`
	Disabled bool   `json:"disabled,omitempty"`
}

// StepResult reports per-step status so a host can highlight the failing step.
type StepResult struct {
	Error string `json:"error,omitempty"`
}

// RecipeResult is the outcome of RunRecipe: the final bytes, per-step status, the
// index of the first failing step (-1 if none), and that step's error for display.
type RecipeResult struct {
	Output   []byte
	Steps    []StepResult
	FailedAt int
	Error    string
}

// flowOnly is the run func for control ops: they are meaningful only to the
// interpreter, never as a standalone Run.
func flowOnly(_ []byte, _ Args) ([]byte, error) {
	return nil, errBadf("this is a flow-control operation; it only runs inside a recipe")
}

type opError string

func (e opError) Error() string { return string(e) }
func errBadf(s string) error    { return opError(s) }

func init() {
	reg(Op{ID: "fork", Name: "Fork", Category: "Flow control", Params: []Param{
		{Name: "splitDelim", Label: "Split delimiter", Type: ParamText, Default: "Line feed"},
		{Name: "mergeDelim", Label: "Merge delimiter", Type: ParamText, Default: "Line feed"},
	}, run: flowOnly})
	reg(Op{ID: "merge", Name: "Merge", Category: "Flow control", run: flowOnly})
	reg(Op{ID: "register", Name: "Register", Category: "Flow control", Params: []Param{
		{Name: "regex", Label: "Extract (regex with capture groups)", Type: ParamText},
	}, run: flowOnly})
}

// RunRecipe executes steps against input. Regular ops apply to every current
// branch; flow-control ops reshape the branch set. On the first error it stops and
// records where.
func RunRecipe(steps []Step, input []byte) RecipeResult {
	res := RecipeResult{FailedAt: -1, Steps: make([]StepResult, len(steps))}
	branches := [][]byte{append([]byte(nil), input...)}
	mergeDelim := []byte("\n")
	forked := false
	registers := map[string]string{}

	for i, st := range steps {
		if st.Disabled {
			continue
		}
		switch st.ID {
		case "fork":
			sd := []byte(delimValue(st.Args.Get("splitDelim")))
			mergeDelim = []byte(delimValue(st.Args.Get("mergeDelim")))
			var nb [][]byte
			for _, b := range branches {
				if len(sd) == 0 {
					nb = append(nb, b)
					continue
				}
				nb = append(nb, bytes.Split(b, sd)...)
			}
			branches, forked = nb, true
		case "merge":
			branches = [][]byte{bytes.Join(branches, mergeDelim)}
			forked = false
		case "register":
			re, err := regexp.Compile(st.Args.Get("regex"))
			if err != nil {
				res.fail(i, err)
				return res.finish(branches, mergeDelim, forked)
			}
			if m := re.FindSubmatch(branches[0]); len(m) > 1 {
				for gi, g := range m[1:] {
					registers["R"+strconv.Itoa(gi)] = string(g)
				}
			}
		default:
			args := substituteRegisters(st.Args, registers)
			for bi, b := range branches {
				out, err := Run(st.ID, b, args)
				if err != nil {
					res.fail(i, err)
					return res.finish(branches, mergeDelim, forked)
				}
				branches[bi] = out
			}
		}
	}
	return res.finish(branches, mergeDelim, forked)
}

func (r *RecipeResult) fail(i int, err error) {
	r.FailedAt = i
	r.Error = err.Error()
	if i >= 0 && i < len(r.Steps) {
		r.Steps[i].Error = err.Error()
	}
}

// finish joins the branches for output: with the fork's merge delimiter if still
// forked, otherwise the single branch.
func (r RecipeResult) finish(branches [][]byte, mergeDelim []byte, forked bool) RecipeResult {
	if forked {
		r.Output = bytes.Join(branches, mergeDelim)
	} else if len(branches) > 0 {
		r.Output = branches[0]
	}
	return r
}

// substituteRegisters replaces $R0, $R1, ... in every argument value with the
// captured register contents. Longest register names first so $R10 beats $R1.
func substituteRegisters(a Args, regs map[string]string) Args {
	if len(regs) == 0 {
		return a
	}
	names := make([]string, 0, len(regs))
	for k := range regs {
		names = append(names, k)
	}
	// Descending length keeps $R1 from clobbering the prefix of $R10.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if len(names[j]) > len(names[i]) {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	out := make(Args, len(a))
	for k, v := range a {
		for _, n := range names {
			v = strings.ReplaceAll(v, "$"+n, regs[n])
		}
		out[k] = v
	}
	return out
}
