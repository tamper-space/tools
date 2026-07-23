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
	reg(Op{ID: "subsection", Name: "Subsection", Category: "Flow control", Params: []Param{
		{Name: "regex", Label: "Section (regex)", Type: ParamText},
	}, run: flowOnly})
	reg(Op{ID: "label", Name: "Label", Category: "Flow control", Params: []Param{
		{Name: "name", Label: "Name", Type: ParamText},
	}, run: flowOnly})
	reg(Op{ID: "jump", Name: "Jump", Category: "Flow control", Params: []Param{
		{Name: "label", Label: "Label", Type: ParamText},
		{Name: "maxJumps", Label: "Max jumps", Type: ParamNumber, Default: "10"},
	}, run: flowOnly})
	reg(Op{ID: "conditional-jump", Name: "Conditional Jump", Category: "Flow control", Params: []Param{
		{Name: "regex", Label: "Match (regex)", Type: ParamText},
		{Name: "label", Label: "Label", Type: ParamText},
		{Name: "maxJumps", Label: "Max jumps", Type: ParamNumber, Default: "10"},
	}, run: flowOnly})
}

// iterCap bounds total step executions so a jump loop can never hang the engine,
// independent of any per-jump maxJumps.
const iterCap = 100000

// RunRecipe executes steps against input via a program counter, so jumps can loop.
// Regular ops apply to every branch (or, under a subsection, only to the regex
// matches within each branch); flow-control ops reshape the branch set or move the
// PC. On the first error it stops and records where.
func RunRecipe(steps []Step, input []byte) RecipeResult {
	res := RecipeResult{FailedAt: -1, Steps: make([]StepResult, len(steps))}
	branches := [][]byte{append([]byte(nil), input...)}
	mergeDelim := []byte("\n")
	forked := false
	registers := map[string]string{}
	var subsection *regexp.Regexp

	// Pre-scan label positions; per-jump counters cap loops alongside the global iterCap.
	labels := map[string]int{}
	for i, st := range steps {
		if st.ID == "label" && !st.Disabled {
			labels[strings.TrimSpace(st.Args.Get("name"))] = i
		}
	}
	jumpCounts := map[int]int{}

	// applyRegular runs a normal op over the branches, honoring an active subsection
	// (op applies only to the regex matches within each branch).
	applyRegular := func(id string, args Args) error {
		for bi, b := range branches {
			if subsection != nil {
				var innerErr error
				out := subsection.ReplaceAllFunc(b, func(m []byte) []byte {
					if innerErr != nil {
						return m
					}
					o, err := Run(id, m, args)
					if err != nil {
						innerErr = err
						return m
					}
					return o
				})
				if innerErr != nil {
					return innerErr
				}
				branches[bi] = out
			} else {
				out, err := Run(id, b, args)
				if err != nil {
					return err
				}
				branches[bi] = out
			}
		}
		return nil
	}

	for pc, iters := 0, 0; pc < len(steps); pc++ {
		if iters++; iters > iterCap {
			res.fail(pc, errBadf("recipe exceeded the iteration limit (possible infinite loop)"))
			return res.finish(branches, mergeDelim, forked)
		}
		st := steps[pc]
		if st.Disabled {
			continue
		}
		switch st.ID {
		case "label":
			// marker only
		case "fork":
			sd := []byte(delimValue(delimArg(st.Args.Get("splitDelim"), "Line feed")))
			mergeDelim = []byte(delimValue(delimArg(st.Args.Get("mergeDelim"), "Line feed")))
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
			if subsection != nil {
				subsection = nil // end the subsection; data is already spliced
			} else {
				branches = [][]byte{bytes.Join(branches, mergeDelim)}
				forked = false
			}
		case "subsection":
			re, err := regexp.Compile(st.Args.Get("regex"))
			if err != nil {
				res.fail(pc, err)
				return res.finish(branches, mergeDelim, forked)
			}
			subsection = re
		case "register":
			re, err := regexp.Compile(st.Args.Get("regex"))
			if err != nil {
				res.fail(pc, err)
				return res.finish(branches, mergeDelim, forked)
			}
			if m := re.FindSubmatch(branches[0]); len(m) > 1 {
				for gi, g := range m[1:] {
					registers["R"+strconv.Itoa(gi)] = string(g)
				}
			}
		case "jump":
			if target, ok := labels[strings.TrimSpace(st.Args.Get("label"))]; ok && jumpCounts[pc] < st.Args.Int("maxJumps", 10) {
				jumpCounts[pc]++
				pc = target // for-loop pc++ lands us on the step after the label
				continue
			}
		case "conditional-jump":
			re, err := regexp.Compile(st.Args.Get("regex"))
			if err != nil {
				res.fail(pc, err)
				return res.finish(branches, mergeDelim, forked)
			}
			if target, ok := labels[strings.TrimSpace(st.Args.Get("label"))]; ok && jumpCounts[pc] < st.Args.Int("maxJumps", 10) && re.Match(branches[0]) {
				jumpCounts[pc]++
				pc = target
				continue
			}
		default:
			if err := applyRegular(st.ID, substituteRegisters(st.Args, registers)); err != nil {
				res.fail(pc, err)
				return res.finish(branches, mergeDelim, forked)
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
