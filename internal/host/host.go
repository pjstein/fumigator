package host

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/pjstein/fumigator/internal/findings"
	_ "github.com/pjstein/fumigator/internal/host/collectors" // registers every collector
	"github.com/pjstein/fumigator/internal/pack"
	"github.com/pjstein/fumigator/internal/version"
)

// Finding is one host check hit. It reuses the repo Finding shape: File holds "table" and
// Match holds the row rendered as key=value pairs, so the same JSON readers work.
type Finding = findings.Finding

type Action struct {
	Finding Finding
	Command string // run by --apply (unless Sudo)
	Sudo    bool
	Suggest string // printed for the person, never run
	Manual  string // the reason
	Ran     bool
	Err     string
}

type ProbeResult struct {
	ID     string
	Cmd    string
	Passed bool
	Detail string
}

type Report struct {
	Pack     string            `json:"pack"`
	Host     string            `json:"host"`
	When     string            `json:"when"`
	Tables   map[string]*Table `json:"tables"`
	Findings []Finding         `json:"findings"`
	Actions  []Action          `json:"actions"`
	Probes   []ProbeResult     `json:"probes"`
}

// Evaluate runs every host check in the pack against the collected tables.
func Evaluate(p *pack.Pack, tables map[string]*Table) ([]Finding, []Action) {
	var out []Finding
	var acts []Action
	for i := range p.Host {
		h := &p.Host[i]
		if h.Platform != "" && h.Platform != runtime.GOOS {
			continue
		}
		t := tables[h.Table]
		if t == nil {
			continue
		}
		var rows []map[string]string
		for _, r := range t.Rows {
			if h.WhereMatch(r) {
				rows = append(rows, r)
			}
		}
		if len(rows) == 0 {
			continue
		}
		if h.Once && h.Version == nil {
			rows = rows[:1]
		}
		for _, r := range rows {
			state, fixed := findings.Present, ""
			cur := rowLabel(r)
			if h.Version != nil {
				state, fixed = classify(p, h.Version, r[h.Version.Column])
				cur = r[h.Version.Column]
				if state == findings.OK {
					continue
				}
			}
			f := Finding{
				Pack: p.ID, File: h.Table, Detector: h.ID, State: state, Current: cur, Fixed: fixed,
				Severity: h.SeverityFor(string(state)), Match: renderRow(r), Note: h.Note,
			}
			fx, hasFix := h.Fix[string(state)]
			switch {
			case !hasFix:
				f.Fix = "manual"
			case fx.Command != "" && !fx.Sudo:
				f.Fix = "tool"
				f.FixText = interpolate(fx.Command, r, fixed)
			default:
				f.Fix = "manual"
				f.FixText = interpolate(fx.Command, r, fixed)
			}
			if fx.Manual != "" {
				f.Note = strings.TrimSpace(interpolate(fx.Manual, r, fixed) + " " + f.Note)
			}
			out = append(out, f)
			acts = append(acts, Action{Finding: f, Command: f.FixText, Sudo: fx.Sudo, Suggest: interpolate(fx.Suggest, r, fixed), Manual: f.Note})
			if h.Once && h.Version != nil {
				break
			}
		}
	}
	sort.SliceStable(acts, func(i, j int) bool {
		return findings.SeverityRank[acts[i].Finding.Severity] < findings.SeverityRank[acts[j].Finding.Severity]
	})
	out = out[:0]
	for _, a := range acts {
		out = append(out, a.Finding)
	}
	return out, acts
}

func classify(p *pack.Pack, hv *pack.HostVersion, ver string) (findings.State, string) {
	num := version.Numeric(ver)
	if num == "" {
		return findings.Unknown, ""
	}
	if floor, ok := p.Versions[hv.Table]["*"]; ok {
		if floor == "pending" {
			return findings.Unknown, ""
		}
		if version.Less(num, floor) {
			return findings.Vulnerable, floor
		}
		return findings.OK, floor
	}
	parts := version.Parts(num)
	lp := min(parts, hv.LineParts)
	line := version.Line(num, lp)
	if p.IsEOL(hv.Table, line) {
		return findings.EOL, ""
	}
	fixed := p.Fixed(hv.Table, line)
	if fixed == "" {
		return findings.Unknown, ""
	}
	if parts < hv.PinParts {
		return findings.Floating, fixed
	}
	if version.Less(num, fixed) {
		return findings.Vulnerable, fixed
	}
	return findings.OK, fixed
}

func interpolate(s string, row map[string]string, fixed string) string {
	s = strings.ReplaceAll(s, "{fixed}", fixed)
	for k, v := range row {
		s = strings.ReplaceAll(s, "{"+k+"}", v)
	}
	return s
}

func rowLabel(r map[string]string) string {
	for _, k := range []string{"alias", "app", "name", "path", "version"} {
		if v, ok := r[k]; ok && v != "" {
			return v
		}
	}
	return renderRow(r)
}

func renderRow(r map[string]string) string {
	keys := make([]string, 0, len(r))
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+r[k])
	}
	return strings.Join(parts, " ")
}

// Apply runs each non-sudo command once (deduplicated), logging output to w.
func Apply(acts []Action, logf func(string)) []Action {
	seen := map[string]bool{}
	for i := range acts {
		a := &acts[i]
		if a.Command == "" || a.Sudo {
			continue
		}
		if seen[a.Command] {
			a.Ran = true
			continue
		}
		seen[a.Command] = true
		logf("$ " + a.Command)
		c := exec.Command("bash", "-lc", a.Command)
		var out bytes.Buffer
		c.Stdout, c.Stderr = &out, &out
		err := c.Run()
		if s := strings.TrimSpace(out.String()); s != "" {
			logf(s)
		}
		if err != nil {
			a.Err = strings.TrimSpace(err.Error())
			logf("FAILED: " + a.Err)
		} else {
			a.Ran = true
		}
	}
	return acts
}

// Probe runs the pack's verify block. A "fails" probe passes when the command exits non-zero;
// a version_at_least probe passes when stdout parses as a version at or above the table's fix.
func Probe(p *pack.Pack) []ProbeResult {
	var out []ProbeResult
	for _, pr := range p.Verify {
		if len(pr.Run) == 0 {
			continue
		}
		if _, err := exec.LookPath(pr.Run[0]); err != nil {
			continue // client not installed: nothing to verify
		}
		c := exec.Command(pr.Run[0], pr.Run[1:]...)
		var buf bytes.Buffer
		c.Stdout, c.Stderr = &buf, &buf
		done := make(chan error, 1)
		go func() { done <- c.Run() }()
		var err error
		select {
		case err = <-done:
		case <-time.After(30 * time.Second):
			_ = c.Process.Kill() // best effort; the timeout is the reported error
			err = fmt.Errorf("timeout")
		}
		res := ProbeResult{ID: pr.ID, Cmd: strings.Join(pr.Run, " ")}
		switch {
		case pr.Expect.Fails:
			res.Passed = err != nil
			if !res.Passed {
				res.Detail = "STILL TRUSTS (fetched the test page)"
			}
		case pr.Expect.VersionAtLeast != "":
			v := version.Numeric(strings.TrimSpace(buf.String()))
			fixed := p.Fixed(pr.Expect.VersionAtLeast, version.Line(v, 2))
			if fixed == "" {
				fixed = p.Versions[pr.Expect.VersionAtLeast]["*"]
			}
			res.Passed = v != "" && fixed != "" && !version.Less(v, fixed)
			res.Detail = v + " vs " + fixed
		default:
			res.Passed = err == nil
		}
		out = append(out, res)
	}
	return out
}

// NeedsYou renders the items the tool will not run as a commented bash script: one comment
// with severity, check and reason, then the command (sudo commands, suggested commands, and
// commands that failed under --apply). Items with no known command get a comment only.
func NeedsYou(p *pack.Pack, acts []Action, applied bool) string {
	var b strings.Builder
	n := 0
	for _, a := range acts {
		cmd := ""
		switch {
		case a.Sudo:
			cmd = a.Command
		case a.Err != "":
			cmd = a.Command
		case a.Command != "" && !applied:
			continue // will run under --apply
		case a.Command != "" && a.Ran:
			continue
		default:
			cmd = a.Suggest
		}
		f := a.Finding
		n++
		what := f.Current
		if f.Fixed != "" {
			what += " -> " + f.Fixed
		}
		fmt.Fprintf(&b, "# [%s] %s: %s (%s)\n", f.Severity, f.Detector, what, f.State)
		if a.Err != "" {
			fmt.Fprintf(&b, "#   failed under --apply: %s\n", a.Err)
		}
		if a.Manual != "" {
			fmt.Fprintf(&b, "#   %s\n", a.Manual)
		} else if f.Note != "" {
			fmt.Fprintf(&b, "#   %s\n", f.Note)
		}
		if cmd != "" {
			fmt.Fprintf(&b, "%s\n", cmd)
		} else {
			b.WriteString("#   (no single command; decide and act by hand)\n")
		}
		b.WriteString("\n")
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("#!/usr/bin/env bash\n# %s on %s: %d item(s) fumigator did not run. Read each reason, delete what you don't want, then run.\n# Copy it first if you will run fumigator host again meanwhile: a re-run replaces this file.\nset -x\n\n", p.ID, Hostname(), n) + b.String()
}

func Hostname() string { h, _ := os.Hostname(); return h }
