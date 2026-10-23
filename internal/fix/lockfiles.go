package fix

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// lockTools maps a lockfile name to the program that owns it. A lock command in a pack may
// list alternatives joined by "||"; only the one whose program owns the target lockfile runs.
// Running uv in a Poetry project "succeeds" by writing a new uv.lock and leaves poetry.lock
// untouched, so trying alternatives in order is wrong.
var lockTools = map[string][]string{
	"uv.lock":           {"uvx", "uv"},
	"poetry.lock":       {"poetry"},
	"pdm.lock":          {"pdm"},
	"Pipfile.lock":      {"pipenv"},
	"Cargo.lock":        {"cargo"},
	"composer.lock":     {"composer"},
	"mix.lock":          {"mix"},
	"package-lock.json": {"npm"},
	"yarn.lock":         {"yarn"},
	"pnpm-lock.yaml":    {"pnpm"},
	"go.mod":            {"go"},
}

// commandFor picks the alternative in cmd that owns lockfile. Commands with no alternative
// for a known lockfile return "" (the finding becomes manual); unknown files keep cmd as is.
func commandFor(cmd, lockfile string) string {
	owners, known := lockTools[filepath.Base(lockfile)]
	if !known {
		return cmd
	}
	alts := strings.Split(cmd, "||")
	if len(alts) == 1 && !strings.Contains(cmd, "&&") {
		// a single command: still refuse an obvious mismatch (uv lock on poetry.lock)
		if !ownsCommand(owners, cmd) {
			return ""
		}
		return strings.TrimSpace(cmd)
	}
	for _, a := range alts {
		if ownsCommand(owners, a) {
			return strings.TrimSpace(a)
		}
	}
	return ""
}

func ownsCommand(owners []string, cmd string) bool {
	w := strings.Fields(strings.TrimSpace(cmd))
	if len(w) == 0 {
		return false
	}
	return slices.Contains(owners, w[0])
}

// uvReleases are tried newest first when regenerating a uv.lock; the first one whose output
// keeps the lock's revision wins. Measured 2026-10-22: 0.12+ writes revision 5, 0.8–0.11
// revision 3, 0.6–0.7 revision 2, older none.
var uvReleases = []string{"0.13.5", "0.12.24", "0.11.33", "0.10.12", "0.9.30", "0.8.24", "0.7.22", "0.6.17", "0.5.31"}

var (
	uvxCmd     = regexp.MustCompile(`^\s*uvx\s+(?:-q\s+)?uv@[\w.]+\s+`)
	uvCmd      = regexp.MustCompile(`^\s*uv\s+`)
	revisionRe = regexp.MustCompile(`(?m)^revision = (\d+)\s*$`)
)

func lockRevision(b []byte) string {
	if m := revisionRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return "1"
}

// runUVKeepingRevision runs a uv lock command so the lock keeps its revision: each uv release
// is tried newest first, and the original file is restored between tries and on failure.
// It returns the release used, or an error describing why none kept the revision.
func runUVKeepingRevision(dir, cmd string) (string, string, error) {
	lock := filepath.Join(dir, "uv.lock")
	orig, err := os.ReadFile(lock)
	if err != nil {
		return "", "", fmt.Errorf("read uv.lock: %w", err)
	}
	want := lockRevision(orig)
	args := uvxCmd.ReplaceAllString(cmd, "")
	if args == cmd {
		args = uvCmd.ReplaceAllString(cmd, "")
	}
	var lastOut string
	for _, v := range uvReleases {
		run := "uvx -q uv@" + v + " " + args
		c := exec.Command("sh", "-c", run)
		c.Dir = dir
		var out bytes.Buffer
		c.Stdout, c.Stderr = &out, &out
		err := c.Run()
		got, _ := os.ReadFile(lock)
		if err == nil && lockRevision(got) == want {
			return v, run, nil
		}
		lastOut = out.String()
		if werr := os.WriteFile(lock, orig, 0o644); werr != nil {
			return "", "", werr
		}
		if err != nil && !strings.Contains(lastOut, "revision") {
			// a resolution failure is not a version mismatch; older releases will not fix it
			return "", "", fmt.Errorf("%s", tailOf(lastOut))
		}
	}
	return "", "", fmt.Errorf("no uv release kept lock revision %s: %s", want, tailOf(lastOut))
}

func tailOf(s string) string {
	t := strings.Join(strings.Fields(s), " ")
	if len(t) > 300 {
		t = t[len(t)-300:]
	}
	return t
}

// packageOf returns the package name a lockfile finding is about ("grpcio 1.80.0" -> grpcio).
func packageOf(current string) string {
	if f := strings.Fields(current); len(f) > 0 {
		return f[0]
	}
	return ""
}

// rollbackPins undoes manifest edits that pin pkg in dir when that directory's lock could not
// be regenerated, so the manifest and the lock never disagree (uv sync --locked would fail).
func (r *remediator) rollbackPins(dir, pkg string) []Edit {
	if pkg == "" {
		return nil
	}
	pkgRe := regexp.MustCompile(`(?i)(^|[^\w-])` + regexp.QuoteMeta(pkg) + `([^\w-]|$)`)
	var kept, undone []Edit
	for _, e := range r.res.Edits {
		base := strings.ToLower(filepath.Base(e.File))
		manifest := base == "pyproject.toml" || strings.HasPrefix(base, "requirements") || strings.HasPrefix(base, "constraints") || base == "setup.py" || base == "setup.cfg"
		if filepath.Dir(e.File) != dir || !manifest || e.Before == "" || !pkgRe.MatchString(e.After) {
			kept = append(kept, e)
			continue
		}
		p := filepath.Join(r.repo, e.File)
		b, err := os.ReadFile(p)
		if err != nil {
			kept = append(kept, e)
			continue
		}
		lines := strings.Split(string(b), "\n")
		if e.Line-1 < len(lines) && lines[e.Line-1] == e.After {
			lines[e.Line-1] = e.Before
			if os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644) == nil {
				undone = append(undone, e)
				continue
			}
		}
		kept = append(kept, e)
	}
	r.res.Edits = kept
	return undone
}
