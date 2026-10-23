// Package pack loads and validates a vulnerability pack: one YAML file that holds the
// advisory metadata, the fixed-version tables, the detectors, and the verification probes.
// Packs are data. The engine implements a small fixed set of detector types.
package pack

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/pjstein/fumigator/internal/version"
)

type Pack struct {
	ID        string `yaml:"id"`
	Title     string `yaml:"title"`
	Advisory  string `yaml:"advisory"`
	Published string `yaml:"published"`
	Updated   string `yaml:"updated"`
	Summary   string `yaml:"summary"` // two sentences for PR bodies and Slack

	// Versions: table name -> (line -> fixed version). A line is "8.3" or "22".
	Versions map[string]map[string]string `yaml:"versions"`
	// EOL: table name -> lines with no fixed release.
	EOL map[string][]string `yaml:"eol"`
	// Strings: named string lists, for content detectors (bad root names, etc).
	Strings map[string][]string `yaml:"strings"`

	Detectors []Detector  `yaml:"detectors"`
	Host      []HostCheck `yaml:"host"`
	Verify    []Probe     `yaml:"verify"`

	Dir string `yaml:"-"`
}

// Detector types:
//
//	regex-version  Pattern with (?P<version>...) and optionally (?P<name>...). The version is
//	               looked up in Table (or in Tables[name-basename]) by its first LineParts parts.
//	               States: vulnerable, eol, floating (fewer than PinParts parts), ok, unknown.
//	content        Any of the strings in Any (literal, or regex when prefixed "re:") appears
//	               in the file. State: present.
//	pair           Sequential name/version lines (Cargo.lock, uv.lock, poetry.lock, mix.lock).
//	               NamePattern captures (?P<name>), VersionPattern captures (?P<version>);
//	               only names listed in Packages are checked, each against Table[name].
//	absent         Trigger lines start a block (until the next trigger); if no line in the
//	               block matches Require, report state absent at the trigger line.
type Detector struct {
	ID      string   `yaml:"id"`
	Type    string   `yaml:"type"`
	Files   []string `yaml:"files"`    // doublestar globs, matched against repo-relative paths
	Exclude []string `yaml:"exclude"`  // globs to skip (testdata/, fixtures/)
	MaxSize int64    `yaml:"max_size"` // bytes; 0 = engine default (5 MB)
	Note    string   `yaml:"note"`

	// regex-version
	Pattern   string            `yaml:"pattern"`
	Table     string            `yaml:"table"`
	Tables    map[string]string `yaml:"tables"` // name basename -> table
	LineParts int               `yaml:"line_parts"`
	PinParts  int               `yaml:"pin_parts"`
	Skip      []string          `yaml:"skip"`   // captured versions to ignore ("stable", "latest", "$")
	After     string            `yaml:"after"`  // only match within Within lines after a line matching this
	Within    int               `yaml:"within"` // default 5

	// content
	Any []string `yaml:"any"`

	// pair
	NamePattern    string            `yaml:"name_pattern"`
	VersionPattern string            `yaml:"version_pattern"`
	Packages       map[string]string `yaml:"packages"` // package name -> table name

	// absent
	Trigger string `yaml:"trigger"`
	Require string `yaml:"require"`
	When    string `yaml:"when"` // optional: only blocks containing a line matching this are checked

	Severity map[string]string `yaml:"severity"` // state -> severity
	Fix      map[string]Fix    `yaml:"fix"`      // state -> fix

	// compiled
	re, nameRe, verRe, trigRe, reqRe, afterRe, whenRe *regexp.Regexp
	anyRe                                             []*regexp.Regexp
	anyLit                                            []string
}

type Fix struct {
	Kind    string `yaml:"kind"`    // rewrite | insert-after | tool | manual | none
	Capture string `yaml:"capture"` // rewrite: which capture to replace (default "version")
	Pattern string `yaml:"pattern"` // rewrite: optional regex applied to the matched line; To may use ${1}
	To      string `yaml:"to"`      // rewrite/insert-after text; {fixed} {name} {current} interpolated
	Command string `yaml:"command"` // tool: shell command; {fixed} {name} interpolated
}

// HostCheck queries one collector table on the local machine, osquery-style: rows are filtered
// by Where (literal or "re:" regex per column), then either a Version comparison classifies each
// row (vulnerable / eol / floating / ok / unknown) or, with no Version, every matching row is
// "present". Fix commands interpolate {col} for any column of the row plus {fixed} and {line}.
type HostCheck struct {
	ID       string             `yaml:"id"`
	Table    string             `yaml:"table"`
	Where    map[string]string  `yaml:"where"`
	Version  *HostVersion       `yaml:"version"`
	Severity map[string]string  `yaml:"severity"`
	Fix      map[string]HostFix `yaml:"fix"`
	Note     string             `yaml:"note"`
	Once     bool               `yaml:"once"`     // collapse all matching rows into one finding / one command
	Platform string             `yaml:"platform"` // darwin | linux | "" (any)

	whereRe  map[string]*regexp.Regexp
	whereNot map[string]*regexp.Regexp
}

type HostVersion struct {
	Column    string `yaml:"column"`
	Table     string `yaml:"table"`
	LineParts int    `yaml:"line_parts"`
	PinParts  int    `yaml:"pin_parts"`
}

type HostFix struct {
	Command string `yaml:"command"` // shell command the tool runs with --apply; empty means manual
	Sudo    bool   `yaml:"sudo"`    // never run automatically; printed for the user
	Suggest string `yaml:"suggest"` // a command for the user to run after deciding; never run by the tool
	Manual  string `yaml:"manual"`  // the reason / decision, shown with the suggested command
}

type Probe struct {
	ID     string   `yaml:"id"`
	Run    []string `yaml:"run"`
	Expect struct {
		Fails          bool   `yaml:"fails"`            // probe passes when the command exits non-zero
		VersionAtLeast string `yaml:"version_at_least"` // table name; stdout parsed as a version
	} `yaml:"expect"`
	Note string `yaml:"note"`
}

var validTypes = map[string]bool{"regex-version": true, "content": true, "pair": true, "absent": true}
var validFix = map[string]bool{"rewrite": true, "insert-after": true, "tool": true, "manual": true, "none": true}
var validSev = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

// Embedded is the packs filesystem compiled into the binary (packs/<id>/pack.yaml), set by
// the main package. Packs on disk take precedence; this is the fallback for a bare binary.
var Embedded fs.FS

// Load reads <dir>/pack.yaml and compiles every pattern.
func Load(dir string) (*Pack, error) {
	b, err := os.ReadFile(filepath.Join(dir, "pack.yaml"))
	if err != nil {
		return nil, err
	}
	return parse(b, dir)
}

func parse(b []byte, dir string) (*Pack, error) {
	var p Pack
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	p.Dir = dir
	if err := p.compile(); err != nil {
		return nil, fmt.Errorf("pack %s: %w", p.ID, err)
	}
	return &p, nil
}

// Find resolves a pack reference: a directory, an id under packsDir, or an embedded id.
func Find(packsDir, ref string) (*Pack, error) {
	if st, err := os.Stat(ref); err == nil && st.IsDir() {
		return Load(ref)
	}
	if p, err := Load(filepath.Join(packsDir, ref)); err == nil {
		return p, nil
	}
	if Embedded != nil {
		if b, err := fs.ReadFile(Embedded, "packs/"+ref+"/pack.yaml"); err == nil {
			return parse(b, "embedded:"+ref)
		}
	}
	return nil, fmt.Errorf("pack %q: not under %s and not built in (fumigator list)", ref, packsDir)
}

// List returns every pack id available: on disk under packsDir first, then embedded ones
// not shadowed by a directory of the same id.
func List(packsDir string) []string {
	seen := map[string]bool{}
	var out []string
	if ents, err := os.ReadDir(packsDir); err == nil {
		for _, e := range ents {
			if e.IsDir() && !seen[e.Name()] {
				seen[e.Name()] = true
				out = append(out, e.Name())
			}
		}
	}
	if Embedded != nil {
		if ents, err := fs.ReadDir(Embedded, "packs"); err == nil {
			for _, e := range ents {
				if e.IsDir() && !seen[e.Name()] {
					seen[e.Name()] = true
					out = append(out, e.Name())
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func (p *Pack) compile() error {
	if p.ID == "" {
		return fmt.Errorf("missing id")
	}
	if len(p.Detectors) == 0 {
		return fmt.Errorf("no detectors")
	}
	seen := map[string]bool{}
	for i := range p.Detectors {
		d := &p.Detectors[i]
		if d.ID == "" || seen[d.ID] {
			return fmt.Errorf("detector %d: missing or duplicate id %q", i, d.ID)
		}
		seen[d.ID] = true
		if !validTypes[d.Type] {
			return fmt.Errorf("%s: unknown type %q", d.ID, d.Type)
		}
		if len(d.Files) == 0 {
			return fmt.Errorf("%s: no files globs", d.ID)
		}
		var err error
		switch d.Type {
		case "regex-version":
			if d.re, err = regexp.Compile("(?m)" + d.Pattern); err != nil {
				return fmt.Errorf("%s: pattern: %w", d.ID, err)
			}
			if d.re.SubexpIndex("version") < 0 {
				return fmt.Errorf("%s: pattern needs a (?P<version>...) group", d.ID)
			}
			if d.Table == "" && len(d.Tables) == 0 {
				return fmt.Errorf("%s: needs table or tables", d.ID)
			}
			if len(d.Tables) > 0 && d.re.SubexpIndex("name") < 0 {
				return fmt.Errorf("%s: tables needs a (?P<name>...) group", d.ID)
			}
			for _, t := range d.allTables() {
				if _, ok := p.Versions[t]; !ok {
					return fmt.Errorf("%s: table %q not in versions", d.ID, t)
				}
			}
			if d.LineParts == 0 {
				d.LineParts = 2
			}
			if d.PinParts == 0 {
				d.PinParts = 3
			}
			if d.After != "" {
				if d.afterRe, err = regexp.Compile(d.After); err != nil {
					return fmt.Errorf("%s: after: %w", d.ID, err)
				}
				if d.Within == 0 {
					d.Within = 5
				}
			}
		case "content":
			if len(d.Any) == 0 {
				return fmt.Errorf("%s: content needs any", d.ID)
			}
			for _, s := range d.Any {
				if after, ok := strings.CutPrefix(s, "re:"); ok {
					r, err := regexp.Compile(after)
					if err != nil {
						return fmt.Errorf("%s: %w", d.ID, err)
					}
					d.anyRe = append(d.anyRe, r)
				} else if after, ok := strings.CutPrefix(s, "$"); ok {
					lst, ok := p.Strings[after]
					if !ok {
						return fmt.Errorf("%s: strings list %s not defined", d.ID, s)
					}
					d.anyLit = append(d.anyLit, lst...)
				} else {
					d.anyLit = append(d.anyLit, s)
				}
			}
		case "pair":
			if d.nameRe, err = regexp.Compile(d.NamePattern); err != nil {
				return fmt.Errorf("%s: name_pattern: %w", d.ID, err)
			}
			if d.verRe, err = regexp.Compile(d.VersionPattern); err != nil {
				return fmt.Errorf("%s: version_pattern: %w", d.ID, err)
			}
			if d.nameRe.SubexpIndex("name") < 0 || d.verRe.SubexpIndex("version") < 0 {
				return fmt.Errorf("%s: pair needs (?P<name>) and (?P<version>) groups", d.ID)
			}
			for pkg, t := range d.Packages {
				if _, ok := p.Versions[t]; !ok {
					return fmt.Errorf("%s: package %s -> table %q not in versions", d.ID, pkg, t)
				}
			}
		case "absent":
			if d.trigRe, err = regexp.Compile(d.Trigger); err != nil {
				return fmt.Errorf("%s: trigger: %w", d.ID, err)
			}
			if d.reqRe, err = regexp.Compile(d.Require); err != nil {
				return fmt.Errorf("%s: require: %w", d.ID, err)
			}
			if d.When != "" {
				if d.whenRe, err = regexp.Compile(d.When); err != nil {
					return fmt.Errorf("%s: when: %w", d.ID, err)
				}
			}
		}
		for st, s := range d.Severity {
			if !validSev[s] {
				return fmt.Errorf("%s: severity[%s]=%q invalid", d.ID, st, s)
			}
		}
		for st, f := range d.Fix {
			if !validFix[f.Kind] {
				return fmt.Errorf("%s: fix[%s].kind=%q invalid", d.ID, st, f.Kind)
			}
			if f.Pattern != "" {
				if _, err := regexp.Compile(f.Pattern); err != nil {
					return fmt.Errorf("%s: fix[%s].pattern: %w", d.ID, st, err)
				}
			}
		}
	}
	for i := range p.Host {
		h := &p.Host[i]
		if h.ID == "" || h.Table == "" {
			return fmt.Errorf("host[%d]: id and table are required", i)
		}
		h.whereRe = map[string]*regexp.Regexp{}
		for col, v := range h.Where {
			if after, ok := strings.CutPrefix(v, "re:"); ok {
				r, err := regexp.Compile(after)
				if err != nil {
					return fmt.Errorf("host %s: where[%s]: %w", h.ID, col, err)
				}
				h.whereRe[col] = r
			}
		}
		if h.Version != nil {
			if h.Version.Column == "" || h.Version.Table == "" {
				return fmt.Errorf("host %s: version needs column and table", h.ID)
			}
			if _, ok := p.Versions[h.Version.Table]; !ok {
				return fmt.Errorf("host %s: version table %q not in versions", h.ID, h.Version.Table)
			}
			if h.Version.LineParts == 0 {
				h.Version.LineParts = 2
			}
			if h.Version.PinParts == 0 {
				h.Version.PinParts = 3
			}
		}
		for st, sv := range h.Severity {
			if !validSev[sv] {
				return fmt.Errorf("host %s: severity[%s]=%q invalid", h.ID, st, sv)
			}
		}
	}
	return nil
}

// WhereMatch reports whether a row satisfies every Where clause: a literal, "re:" (must
// match) or "!re:" (must not match).
func (h *HostCheck) WhereMatch(row map[string]string) bool {
	for col, v := range h.Where {
		if r, ok := h.whereNot[col]; ok {
			if r.MatchString(row[col]) {
				return false
			}
			continue
		}
		if r, ok := h.whereRe[col]; ok {
			if !r.MatchString(row[col]) {
				return false
			}
		} else if row[col] != v {
			return false
		}
	}
	return true
}

func (h *HostCheck) SeverityFor(state string) string {
	if s, ok := h.Severity[state]; ok {
		return s
	}
	return "info"
}

func (d *Detector) allTables() []string {
	var out []string
	if d.Table != "" {
		out = append(out, d.Table)
	}
	for _, t := range d.Tables {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Accessors for the engine.
func (d *Detector) Re() *regexp.Regexp      { return d.re }
func (d *Detector) NameRe() *regexp.Regexp  { return d.nameRe }
func (d *Detector) VerRe() *regexp.Regexp   { return d.verRe }
func (d *Detector) TrigRe() *regexp.Regexp  { return d.trigRe }
func (d *Detector) ReqRe() *regexp.Regexp   { return d.reqRe }
func (d *Detector) AfterRe() *regexp.Regexp { return d.afterRe }
func (d *Detector) WhenRe() *regexp.Regexp  { return d.whenRe }
func (d *Detector) AnyRe() []*regexp.Regexp { return d.anyRe }
func (d *Detector) AnyLit() []string        { return d.anyLit }

// SeverityFor returns the configured severity for a state, defaulting to "info".
func (d *Detector) SeverityFor(state string) string {
	if s, ok := d.Severity[state]; ok {
		return s
	}
	return "info"
}

// FixFor returns the configured fix for a state, defaulting to manual.
func (d *Detector) FixFor(state string) Fix {
	if f, ok := d.Fix[state]; ok {
		return f
	}
	return Fix{Kind: "manual"}
}

// Fixed returns the fixed version for a version line in a table, or "" if the line is not listed.
func (p *Pack) Fixed(table, line string) string {
	return p.Versions[table][line]
}

// IsEOL reports whether line (or its major) is listed as end-of-life for the table, or is
// older than every line the table knows a fix for.
func (p *Pack) IsEOL(table, line string) bool {
	major := line
	if i := strings.Index(line, "."); i > 0 {
		major = line[:i]
	}
	for _, e := range p.EOL[table] {
		if e == line || e == major {
			return true
		}
	}
	oldest := ""
	for k := range p.Versions[table] {
		if k == "*" {
			continue
		}
		if oldest == "" || version.Less(k, oldest) {
			oldest = k
		}
	}
	return oldest != "" && version.Less(line, oldest)
}

// Latest returns the highest fixed version in a table (used when pinning a floating tag
// that names no line, e.g. "node:latest").
func (p *Pack) Latest(table string) string {
	var best string
	for _, v := range p.Versions[table] {
		if best == "" || version.Less(best, v) {
			best = v
		}
	}
	return best
}

// Interpolate fills {fixed}, {name}, {current}, {line} in fix text.
func Interpolate(s, fixed, name, current, line string) string {
	r := strings.NewReplacer("{fixed}", fixed, "{name}", name, "{current}", current, "{line}", line)
	return r.Replace(s)
}
