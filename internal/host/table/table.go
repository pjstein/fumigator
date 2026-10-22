// Package table defines what a host collector is and holds the registry of collectors.
// A collector is a named table with fixed columns, osquery-style; packs write host checks
// against the column names, so a collector's columns are its contract.
//
// To add a collector: create internal/host/collectors/<name>.go, implement Collector, and
// register it in init(). Nothing else changes; `fumigator host --collectors` lists it.
package table

import (
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Row is one record; every column is a string so packs can regex-match any of it.
type Row = map[string]string

// Table is a collector's output.
type Table struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
	Rows    []Row    `json:"rows"`
	Err     string   `json:"error,omitempty"`
}

// Options are shared inputs a collector may use.
type Options struct {
	VenvRoots []string // where to look for pyvenv.cfg; empty = common source dirs under $HOME
	BadRoots  []string // subject names a trust store must not contain (from the pack)
	Fast      bool     // skip collectors that need the network or take more than a second
}

// Collector produces one table.
type Collector interface {
	Name() string
	Columns() []string
	Doc() string         // one line: what the table holds and where it comes from
	Platforms() []string // GOOS values, nil = all
	Slow() bool          // skipped with Options.Fast
	Collect(opt Options) ([]Row, error)
}

var (
	mu       sync.Mutex
	registry []Collector
)

// Register adds a collector; called from init() in each collector file.
func Register(c Collector) {
	mu.Lock()
	defer mu.Unlock()
	registry = append(registry, c)
	sort.SliceStable(registry, func(i, j int) bool { return registry[i].Name() < registry[j].Name() })
}

// All returns the registered collectors in name order.
func All() []Collector {
	mu.Lock()
	defer mu.Unlock()
	return append([]Collector(nil), registry...)
}

// ---------- helpers shared by collectors ----------

// Sh runs a command and returns trimmed combined output and whether it exited 0.
// A command that is not on PATH returns ("", false) without spawning anything.
func Sh(name string, args ...string) (string, bool) {
	if _, err := exec.LookPath(name); err != nil {
		return "", false
	}
	c := exec.Command(name, args...)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	return strings.TrimSpace(out.String()), err == nil
}

var verRe = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)

// FirstVersion returns the first dotted version in s, or "".
func FirstVersion(s string) string { return verRe.FindString(s) }

// Major returns the part before the first dot.
func Major(v string) string {
	if i := strings.Index(v, "."); i > 0 {
		return v[:i]
	}
	return v
}

// Home is the user's home directory.
func Home() string { h, _ := os.UserHomeDir(); return h }

// Exists reports whether a path exists.
func Exists(p string) bool { _, err := os.Stat(p); return err == nil }

// IsExec reports whether a path is a regular executable file.
func IsExec(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}

// ContainsAny returns the names from bad that appear in b, in order.
func ContainsAny(b []byte, bad []string) []string {
	var hits []string
	for _, r := range bad {
		if bytes.Contains(b, []byte(r)) {
			hits = append(hits, r)
		}
	}
	return hits
}

// Manager guesses which tool owns an executable from its resolved path.
func Manager(resolved string) string {
	switch {
	case strings.HasPrefix(resolved, "/opt/homebrew/") || strings.HasPrefix(resolved, "/usr/local/Cellar/"):
		return "brew"
	case strings.Contains(resolved, "/.nvm/"):
		return "nvm"
	case strings.Contains(resolved, "/.pyenv/"):
		return "pyenv"
	case strings.Contains(resolved, "/.cargo/"):
		return "cargo"
	case strings.Contains(resolved, "/.bun/"):
		return "bun"
	case strings.Contains(resolved, "/.local/share/uv/tools/"):
		return "uv-tool"
	case strings.Contains(resolved, "/.local/share/mise/"):
		return "mise"
	case strings.Contains(resolved, "/.sdkman/"):
		return "sdkman"
	case strings.Contains(resolved, "/go/bin/"):
		return "go-install"
	case strings.Contains(resolved, "/.local/bin/"):
		return "local"
	case strings.HasPrefix(resolved, "/nix/"):
		return "nix"
	case strings.HasPrefix(resolved, "/usr/bin/") || strings.HasPrefix(resolved, "/Applications/Xcode.app/") || strings.HasPrefix(resolved, "/Library/Developer/"):
		return "apple"
	case strings.HasPrefix(resolved, "/Library/Frameworks/Python.framework/"):
		return "pythonorg"
	case strings.HasPrefix(resolved, "/usr/local/aws-cli/"):
		return "aws-cli"
	}
	return "system"
}
