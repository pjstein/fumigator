// Package findings is the contract between scan, fix, and the per-vulnerability skills.
// One JSON file per repo per pack; summary.md across all of them.
package findings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// State is what the detector concluded about the matched value.
type State string

const (
	Vulnerable State = "vulnerable" // below the fixed version
	EOL        State = "eol"        // on a line with no fixed release
	Floating   State = "floating"   // unpinned; may resolve to an old build
	Present    State = "present"    // signature found (content detectors)
	Absent     State = "absent"     // required step missing (absent detectors)
	Unknown    State = "unknown"    // matched but could not classify; look by hand
	OK         State = "ok"         // informational only; not written unless --all
)

// Severity order for sorting; lower is worse.
var SeverityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

type Finding struct {
	Pack     string `json:"pack"`
	Repo     string `json:"repo"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Detector string `json:"detector"`
	State    State  `json:"state"`
	Current  string `json:"current"`
	Fixed    string `json:"fixed,omitempty"`
	Severity string `json:"severity"`
	Fix      string `json:"fix"` // rewrite | insert-after | tool | manual | none
	FixText  string `json:"fix_text,omitempty"`
	// Replace is the exact substring of Match that a rewrite replaces with FixText.
	// FixPattern, when set, is a regex applied to Match instead, with FixText as the replacement.
	Replace    string `json:"replace,omitempty"`
	FixPattern string `json:"fix_pattern,omitempty"`
	Note       string `json:"note,omitempty"`
	// Match holds the full matched line so the fixer can re-find it if line numbers drift.
	Match string `json:"match,omitempty"`
}

type RepoReport struct {
	Pack     string    `json:"pack"`
	Repo     string    `json:"repo"`
	Name     string    `json:"name"` // report file stem; basename unless that collides
	Files    int       `json:"files_scanned"`
	Findings []Finding `json:"findings"`
	Errors   []string  `json:"errors,omitempty"`
}

func (r *RepoReport) Sort() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if SeverityRank[a.Severity] != SeverityRank[b.Severity] {
			return SeverityRank[a.Severity] < SeverityRank[b.Severity]
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}

func (r *RepoReport) Count(sev string) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func (r *RepoReport) CountFix(kind string) int {
	n := 0
	for _, f := range r.Findings {
		if f.Fix == kind && f.Severity != "info" {
			n++
		}
	}
	return n
}

// Actionable is true when at least one finding is not info.
func (r *RepoReport) Actionable() bool {
	for _, f := range r.Findings {
		if f.Severity != "info" {
			return true
		}
	}
	return false
}

// Names assigns a unique report stem to each repo path: the basename, or, when two repos
// share one, enough parent directories to tell them apart joined with "__".
func Names(repos []string) map[string]string {
	out := map[string]string{}
	count := map[string]int{}
	for _, r := range repos {
		count[filepath.Base(r)]++
	}
	for _, r := range repos {
		base := filepath.Base(r)
		if count[base] == 1 {
			out[r] = base
			continue
		}
		parts := strings.Split(strings.Trim(filepath.ToSlash(r), "/"), "/")
		n := 2
		for {
			if n > len(parts) {
				n = len(parts)
			}
			cand := strings.Join(parts[len(parts)-n:], "__")
			clash := false
			for _, o := range repos {
				if o != r && filepath.Base(o) == base {
					op := strings.Split(strings.Trim(filepath.ToSlash(o), "/"), "/")
					m := min(n, len(op))
					if strings.Join(op[len(op)-m:], "__") == cand {
						clash = true
					}
				}
			}
			if !clash || n == len(parts) {
				out[r] = cand
				break
			}
			n++
		}
	}
	return out
}

// Write stores the report as <dir>/<pack>/<name>.json.
func (r *RepoReport) Write(dir string) (string, error) {
	d := filepath.Join(dir, r.Pack)
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	name := r.Name
	if name == "" {
		name = filepath.Base(r.Repo)
	}
	p := filepath.Join(d, name+".json")
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return "", err
	}
	return p, os.WriteFile(p, b, 0o644)
}

func Read(path string) (*RepoReport, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r RepoReport
	return &r, json.Unmarshal(b, &r)
}

// Summary renders the cross-repo table for one pack.
func Summary(pack, title string, reports []*RepoReport, orphans []string, orgMissing []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — scan summary\n\n", title)
	fmt.Fprintf(&b, "Pack `%s`. %d repos scanned.\n\n", pack, len(reports))
	b.WriteString("| Repo | critical | high | medium | rewrite | tool | manual | top finding |\n|---|---|---|---|---|---|---|---|\n")
	n := 0
	for _, r := range reports {
		if !r.Actionable() {
			continue
		}
		n++
		var top Finding
		for _, f := range r.Findings {
			if f.Severity != "info" {
				top = f
				break
			}
		}
		name := r.Name
		if name == "" {
			name = filepath.Base(r.Repo)
		}
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d | %d | %d | %d | `%s:%d` %s %s |\n",
			name, r.Count("critical"), r.Count("high"), r.Count("medium"),
			r.CountFix("rewrite")+r.CountFix("insert-after"), r.CountFix("tool"), r.CountFix("manual"),
			top.File, top.Line, top.Detector, top.Current)
	}
	if n == 0 {
		b.WriteString("| (no actionable findings) | | | | | | | |\n")
	}
	if len(orphans) > 0 {
		fmt.Fprintf(&b, "\n## Risk files outside any git repo (%d)\n\nInstalls, vendored copies or backups; nothing to PR. Check or delete by hand.\n\n", len(orphans))
		for _, o := range orphans {
			fmt.Fprintf(&b, "- `%s`\n", o)
		}
	}
	if len(orgMissing) > 0 {
		fmt.Fprintf(&b, "\n## Org repos with no local checkout (%d)\n\nRun `fumigator gh sync --org ORG DEST` then re-scan.\n\n", len(orgMissing))
		for _, m := range orgMissing {
			fmt.Fprintf(&b, "- %s\n", m)
		}
	}
	return b.String()
}
