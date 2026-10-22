// Package engine runs a pack's detectors over one repository's files.
package engine

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/pjstein/fumigator/internal/discover"
	"github.com/pjstein/fumigator/internal/findings"
	"github.com/pjstein/fumigator/internal/pack"
	"github.com/pjstein/fumigator/internal/version"
)

const DefaultMaxSize = 5 << 20

type Options struct {
	IncludeOK bool // emit state=ok findings (severity info) for audit trails
	Workers   int  // per-repo file parallelism
}

// MatchesName reports whether a bare file name matches a detector glob that has no path
// component. Used for orphan discovery, where path globs like **/manifests/**/*.yml would
// sweep up every YAML file in an SDK install.
func MatchesName(p *pack.Pack, name string) bool {
	for i := range p.Detectors {
		for _, g := range p.Detectors[i].Files {
			if strings.Contains(g, "/") {
				continue
			}
			if ok, _ := doublestar.Match(g, name); ok {
				return true
			}
		}
	}
	return false
}

// Matches reports whether a repo-relative path is a candidate for any detector in the pack.
func Matches(p *pack.Pack, rel string) bool {
	for i := range p.Detectors {
		if fileMatches(&p.Detectors[i], rel) {
			return true
		}
	}
	return false
}

func fileMatches(d *pack.Detector, rel string) bool {
	rel = filepath.ToSlash(rel)
	base := filepath.Base(rel)
	for _, ex := range d.Exclude {
		if ok, _ := doublestar.Match(ex, rel); ok {
			return false
		}
	}
	for _, g := range d.Files {
		if ok, _ := doublestar.Match(g, rel); ok {
			return true
		}
		if !strings.Contains(g, "/") {
			if ok, _ := doublestar.Match(g, base); ok {
				return true
			}
		}
	}
	return false
}

// ScanRepo runs every detector over the repo's files (from git ls-files) and returns the report.
func ScanRepo(p *pack.Pack, repo string, opt Options) *findings.RepoReport {
	rep := &findings.RepoReport{Pack: p.ID, Repo: repo}
	files, err := discover.Files(repo)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return rep
	}
	return ScanFiles(p, repo, files, opt, rep)
}

// ScanFiles runs the detectors over an explicit list of repo-relative files.
func ScanFiles(p *pack.Pack, repo string, files []string, opt Options, rep *findings.RepoReport) *findings.RepoReport {
	if rep == nil {
		rep = &findings.RepoReport{Pack: p.ID, Repo: repo}
	}
	workers := opt.Workers
	if workers <= 0 {
		workers = 8
	}
	type job struct{ rel string }
	jobs := make(chan job)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Go(func() {
			for j := range jobs {
				fs, errs := scanFile(p, repo, j.rel, opt)
				mu.Lock()
				rep.Findings = append(rep.Findings, fs...)
				rep.Errors = append(rep.Errors, errs...)
				rep.Files++
				mu.Unlock()
			}
		})
	}
	for _, f := range files {
		if Matches(p, f) {
			jobs <- job{f}
		}
	}
	close(jobs)
	wg.Wait()
	rep.Sort()
	return rep
}

func scanFile(p *pack.Pack, repo, rel string, opt Options) (out []findings.Finding, errs []string) {
	var lines []string
	loaded := false
	for i := range p.Detectors {
		d := &p.Detectors[i]
		if !fileMatches(d, rel) {
			continue
		}
		if !loaded {
			max := d.MaxSize
			if max == 0 {
				max = DefaultMaxSize
			}
			var ok bool
			var err error
			lines, ok, err = discover.ReadLines(filepath.Join(repo, rel), max)
			if err != nil {
				errs = append(errs, rel+": "+err.Error())
				return
			}
			if !ok {
				return // oversized or not regular; silently skip
			}
			loaded = true
		}
		var fs []findings.Finding
		switch d.Type {
		case "regex-version":
			fs = regexVersion(p, d, lines)
		case "content":
			fs = content(p, d, lines)
		case "pair":
			fs = pair(p, d, lines)
		case "absent":
			fs = absent(p, d, lines)
		}
		for i := range fs {
			fs[i].Pack, fs[i].Repo, fs[i].File, fs[i].Detector = p.ID, repo, rel, d.ID
			if fs[i].Note == "" {
				fs[i].Note = d.Note
			}
			if fs[i].State == findings.OK && !opt.IncludeOK {
				continue
			}
			out = append(out, fs[i])
		}
	}
	return
}

// classify decides the state of a captured version against a table.
func classify(p *pack.Pack, d *pack.Detector, table, ver string) (state findings.State, fixed string) {
	num := version.Numeric(ver)
	if num == "" {
		return findings.Floating, p.Latest(table)
	}
	if floor, ok := p.Versions[table]["*"]; ok {
		// single-floor table (certifi, deno): any parsed version compares against the floor
		if floor == "pending" {
			return findings.Unknown, ""
		}
		if version.Less(num, floor) {
			return findings.Vulnerable, floor
		}
		return findings.OK, floor
	}
	parts := version.Parts(num)
	lp := min(parts, d.LineParts)
	line := version.Line(num, lp)
	if p.IsEOL(table, line) {
		return findings.EOL, ""
	}
	fixed = p.Fixed(table, line)
	if fixed == "" {
		// line not in the table and not EOL: newer than we know, or a line we don't model
		return findings.Unknown, ""
	}
	if parts < d.PinParts {
		return findings.Floating, fixed
	}
	if version.Less(num, fixed) {
		return findings.Vulnerable, fixed
	}
	return findings.OK, fixed
}

func regexVersion(p *pack.Pack, d *pack.Detector, lines []string) []findings.Finding {
	var out []findings.Finding
	re := d.Re()
	vi := re.SubexpIndex("version")
	ni := re.SubexpIndex("name")
	after := d.AfterRe()
	armedUntil := -1
	for ln, line := range lines {
		if after != nil {
			if after.MatchString(line) {
				armedUntil = ln + d.Within
				continue
			}
			if ln > armedUntil {
				continue
			}
		}
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ver := m[vi]
		if strings.Contains(ver, "$") || contains(d.Skip, ver) {
			continue
		}
		name := ""
		if ni >= 0 {
			name = m[ni]
		}
		table := d.Table
		if len(d.Tables) > 0 {
			base := name
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			t, ok := d.Tables[base]
			if !ok {
				continue
			}
			table = t
		}
		state, fixed := classify(p, d, table, ver)
		f := findings.Finding{Line: ln + 1, State: state, Current: ver, Fixed: fixed, Match: line}
		f.Severity = d.SeverityFor(string(state))
		fx := d.FixFor(string(state))
		f.Fix = fx.Kind
		switch fx.Kind {
		case "rewrite":
			to := fx.To
			if to == "" {
				to = "{fixed}"
			}
			f.FixText = pack.Interpolate(to, fixed, name, ver, version.Line(version.Numeric(ver), d.LineParts))
			f.Replace = ver
			if fx.Capture == "numeric" {
				f.Replace = version.Numeric(ver)
			}
			f.FixPattern = fx.Pattern
		case "insert-after", "tool":
			f.FixText = pack.Interpolate(firstNonEmpty(fx.To, fx.Command), fixed, name, ver, "")
		}
		if name != "" {
			f.Current = name + ":" + ver
		}
		if state == findings.EOL && d.Note == "" {
			f.Note = fmt.Sprintf("%s line %s has no fixed release; needs an upgrade decision", table, version.Line(version.Numeric(ver), d.LineParts))
		}
		out = append(out, f)
	}
	return out
}

func content(_ *pack.Pack, d *pack.Detector, lines []string) []findings.Finding {
	var hits []string
	first := 0
	firstLine := ""
	for ln, line := range lines {
		for _, s := range d.AnyLit() {
			if strings.Contains(line, s) && !contains(hits, s) {
				hits = append(hits, s)
				if first == 0 {
					first, firstLine = ln+1, line
				}
			}
		}
		for _, r := range d.AnyRe() {
			if m := strings.TrimSpace(r.FindString(line)); m != "" && !contains(hits, m) {
				hits = append(hits, m)
				if first == 0 {
					first, firstLine = ln+1, line
				}
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	fx := d.FixFor("present")
	f := findings.Finding{
		Line: first, State: findings.Present, Current: strings.Join(hits, ", "), Match: firstLine,
		Severity: d.SeverityFor("present"), Fix: fx.Kind, FixText: firstNonEmpty(fx.To, fx.Command),
	}
	if fx.Kind == "rewrite" {
		f.Replace = hits[0]
		f.FixPattern = fx.Pattern
	}
	return []findings.Finding{f}
}

func pair(p *pack.Pack, d *pack.Detector, lines []string) []findings.Finding {
	var out []findings.Finding
	nre, vre := d.NameRe(), d.VerRe()
	ni, vi := nre.SubexpIndex("name"), vre.SubexpIndex("version")
	cur := ""
	curLine := 0
	for ln, line := range lines {
		if m := nre.FindStringSubmatch(line); m != nil {
			cur, curLine = m[ni], ln+1
			// mix.lock and similar put name and version on one line
			if m2 := vre.FindStringSubmatch(line); m2 != nil {
				if f, ok := pairCheck(p, d, cur, m2[vi], ln+1, line); ok {
					out = append(out, f)
				}
				cur = ""
			}
			continue
		}
		if cur == "" {
			continue
		}
		if m := vre.FindStringSubmatch(line); m != nil {
			if f, ok := pairCheck(p, d, cur, m[vi], curLine, line); ok {
				out = append(out, f)
			}
			cur = ""
		}
	}
	return out
}

func pairCheck(p *pack.Pack, d *pack.Detector, name, ver string, ln int, line string) (findings.Finding, bool) {
	table, ok := d.Packages[name]
	if !ok {
		return findings.Finding{}, false
	}
	// package tables are keyed by line or by "*" for a single floor
	fixed := ""
	if v, ok := p.Versions[table]["*"]; ok {
		fixed = v
	} else {
		fixed = p.Fixed(table, version.Line(ver, d.LineParts))
		if fixed == "" {
			fixed = p.Latest(table)
		}
	}
	state := findings.OK
	if fixed == "" || fixed == "pending" {
		state = findings.Unknown
	} else if version.Less(ver, fixed) {
		state = findings.Vulnerable
	}
	fx := d.FixFor(string(state))
	return findings.Finding{
		Line: ln, State: state, Current: name + " " + ver, Fixed: fixed, Match: line,
		Severity: d.SeverityFor(string(state)), Fix: fx.Kind,
		FixText: pack.Interpolate(firstNonEmpty(fx.Command, fx.To), fixed, name, ver, ""),
	}, true
}

func absent(_ *pack.Pack, d *pack.Detector, lines []string) []findings.Finding {
	var out []findings.Finding
	trig, req := d.TrigRe(), d.ReqRe()
	var starts []int
	for ln, line := range lines {
		if trig.MatchString(line) {
			starts = append(starts, ln)
		}
	}
	for i, s := range starts {
		end := len(lines)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		found := slices.ContainsFunc(lines[s:end], req.MatchString)
		state := findings.OK
		if !found {
			state = findings.Absent
		}
		fx := d.FixFor(string(state))
		out = append(out, findings.Finding{
			Line: s + 1, State: state, Current: strings.TrimSpace(lines[s]), Match: lines[s],
			Severity: d.SeverityFor(string(state)), Fix: fx.Kind, FixText: firstNonEmpty(fx.To, fx.Command),
		})
	}
	return out
}

func contains(xs []string, s string) bool {
	return slices.Contains(xs, s)
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// Describe prints a one-line human summary for a finding.
func Describe(f findings.Finding) string {
	return fmt.Sprintf("[%-8s] %s:%d  %s  %s -> %s  (%s) %s", f.Severity, f.File, f.Line, f.Detector, f.Current, f.Fixed, f.Fix, f.Note)
}
