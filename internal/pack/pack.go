// Package pack loads and validates a vulnerability pack: one YAML file that holds the
// advisory metadata, the fixed-version tables, the detectors, and the verification probes.
// Packs are data. The engine implements a small fixed set of detector types.
package pack

import (
	"fmt"
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

	Detectors []Detector `yaml:"detectors"`
	Verify    []Probe    `yaml:"verify"`

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

	Severity map[string]string `yaml:"severity"` // state -> severity
	Fix      map[string]Fix    `yaml:"fix"`      // state -> fix

	// compiled
	re, nameRe, verRe, trigRe, reqRe, afterRe *regexp.Regexp
	anyRe                                     []*regexp.Regexp
	anyLit                                    []string
}

type Fix struct {
	Kind    string `yaml:"kind"`    // rewrite | insert-after | tool | manual | none
	Capture string `yaml:"capture"` // rewrite: which capture to replace (default "version")
	Pattern string `yaml:"pattern"` // rewrite: optional regex applied to the matched line; To may use ${1}
	To      string `yaml:"to"`      // rewrite/insert-after text; {fixed} {name} {current} interpolated
	Command string `yaml:"command"` // tool: shell command; {fixed} {name} interpolated
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

// Load reads <dir>/pack.yaml and compiles every pattern.
func Load(dir string) (*Pack, error) {
	b, err := os.ReadFile(filepath.Join(dir, "pack.yaml"))
	if err != nil {
		return nil, err
	}
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

// Find resolves a pack reference: a directory, or an id under packsDir.
func Find(packsDir, ref string) (*Pack, error) {
	if st, err := os.Stat(ref); err == nil && st.IsDir() {
		return Load(ref)
	}
	return Load(filepath.Join(packsDir, ref))
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
				if strings.HasPrefix(s, "re:") {
					r, err := regexp.Compile(strings.TrimPrefix(s, "re:"))
					if err != nil {
						return fmt.Errorf("%s: %w", d.ID, err)
					}
					d.anyRe = append(d.anyRe, r)
				} else if strings.HasPrefix(s, "$") {
					lst, ok := p.Strings[strings.TrimPrefix(s, "$")]
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
	return nil
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
