// Package host inventories the local machine as a set of tables, osquery-style, and lets a
// pack's host checks query them. Collectors shell out to the managers that own each runtime
// (brew, nvm, pyenv, keytool, plutil) so the facts match what those tools would report.
// A manager that is not installed yields an empty table, never an error.
package host

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/pjstein/fumigator/internal/version"
)

// Table is a named list of rows with string columns.
type Table struct {
	Name    string              `json:"name"`
	Columns []string            `json:"columns"`
	Rows    []map[string]string `json:"rows"`
	Err     string              `json:"error,omitempty"`
}

type collector struct {
	name    string
	columns []string
	run     func() ([]map[string]string, error)
}

// Collectors, in table-name order. Column lists are the contract packs write against.
var collectors = []collector{
	{"system", []string{"os", "version", "pending_updates"}, system},
	{"tools", []string{"name", "version", "path", "manager"}, tools},
	{"brew_packages", []string{"name", "version"}, brewPackages},
	{"node_installs", []string{"manager", "version", "major", "path", "default", "superseded"}, nodeInstalls},
	{"python_installs", []string{"kind", "path", "version", "ssl", "certifi", "pip"}, pythonInstalls},
	{"jdk_keystore_aliases", []string{"alias", "keystore"}, jdkAliases},
	{"electron_apps", []string{"app", "version", "major", "path"}, electronApps},
	{"ca_bundles", []string{"path", "owner", "bad_roots"}, caBundles},
	{"php_ini", []string{"path", "upload_progress_enabled"}, phpIni},
}

// Options tune the slower collectors.
type Options struct {
	VenvRoots []string // where to look for pyvenv.cfg; default: common source dirs under $HOME
	BadRoots  []string // subject names a CA bundle must not contain
}

// Collect runs every collector concurrently.
func Collect(opt Options) map[string]*Table {
	out := map[string]*Table{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range collectors {
		wg.Add(1)
		go func(c collector) {
			defer wg.Done()
			t := &Table{Name: c.name, Columns: c.columns}
			rows, err := c.run()
			if err != nil {
				t.Err = err.Error()
			}
			t.Rows = rows
			mu.Lock()
			out[c.name] = t
			mu.Unlock()
		}(c)
	}
	var venvRows, bundleRows []map[string]string
	wg.Add(2)
	go func() { defer wg.Done(); venvRows = venvs(opt.VenvRoots) }()
	go func() { defer wg.Done(); bundleRows = bundleScan(opt.BadRoots) }()
	wg.Wait()
	out["python_installs"].Rows = append(out["python_installs"].Rows, venvRows...)
	out["ca_bundles"].Rows = append(out["ca_bundles"].Rows, bundleRows...)
	for _, t := range out {
		sort.SliceStable(t.Rows, func(i, j int) bool {
			for _, c := range t.Columns {
				if t.Rows[i][c] != t.Rows[j][c] {
					return t.Rows[i][c] < t.Rows[j][c]
				}
			}
			return false
		})
	}
	return out
}

// ---------- helpers ----------

func sh(name string, args ...string) (string, bool) {
	if _, err := exec.LookPath(name); err != nil {
		return "", false
	}
	c := exec.Command(name, args...)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if err := c.Run(); err != nil {
		return strings.TrimSpace(out.String()), false
	}
	return strings.TrimSpace(out.String()), true
}

var verRe = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)

func firstVersion(s string) string { return verRe.FindString(s) }

func major(v string) string {
	if i := strings.Index(v, "."); i > 0 {
		return v[:i]
	}
	return v
}

func home() string { h, _ := os.UserHomeDir(); return h }

// ---------- collectors ----------

func system() ([]map[string]string, error) {
	row := map[string]string{"os": runtime.GOOS, "version": "", "pending_updates": "unknown"}
	if runtime.GOOS == "darwin" {
		v, _ := sh("sw_vers", "-productVersion")
		row["version"] = v
		if out, _ := sh("softwareupdate", "-l"); strings.Contains(out, "Software Update found") {
			row["pending_updates"] = "true"
		} else {
			row["pending_updates"] = "false"
		}
	}
	return []map[string]string{row}, nil
}

// tools: whatever is on PATH, with the version each tool reports and which manager owns it.
func tools() ([]map[string]string, error) {
	type spec struct {
		name string
		args []string
	}
	specs := []spec{
		{"curl", []string{"--version"}}, {"git", []string{"--version"}}, {"go", []string{"version"}},
		{"node", []string{"--version"}}, {"python3", []string{"--version"}}, {"uv", []string{"--version"}},
		{"pixi", []string{"--version"}}, {"rustup", []string{"--version"}}, {"cargo", []string{"--version"}},
		{"java", []string{"-version"}}, {"ruby", []string{"--version"}}, {"gem", []string{"--version"}},
		{"php", []string{"-r", "echo PHP_VERSION;"}}, {"composer", []string{"--version"}},
		{"deno", []string{"--version"}}, {"bun", []string{"--version"}}, {"mise", []string{"--version"}},
		{"elixir", []string{"--version"}}, {"claude", []string{"--version"}}, {"cpanm", []string{"--version"}},
		{"conda", []string{"--version"}}, {"ddev", []string{"--version"}}, {"docker", []string{"--version"}},
	}
	var rows []map[string]string
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range specs {
		wg.Add(1)
		go func(s spec) {
			defer wg.Done()
			p, err := exec.LookPath(s.name)
			if err != nil {
				return
			}
			out, _ := sh(s.name, s.args...)
			v := firstVersion(strings.SplitN(out, "\n", 2)[0])
			if s.name == "go" {
				v = firstVersion(out)
			}
			real, _ := filepath.EvalSymlinks(p)
			mgr := "system"
			switch {
			case strings.HasPrefix(real, "/opt/homebrew/") || strings.HasPrefix(real, "/usr/local/Cellar/"):
				mgr = "brew"
			case strings.Contains(real, "/.nvm/"):
				mgr = "nvm"
			case strings.Contains(real, "/.pyenv/"):
				mgr = "pyenv"
			case strings.Contains(real, "/.cargo/"):
				mgr = "rustup"
			case strings.Contains(real, "/.bun/"):
				mgr = "bun"
			case strings.Contains(real, "/.local/share/mise/"):
				mgr = "mise"
			case strings.Contains(real, "/.sdkman/"):
				mgr = "sdkman"
			case strings.HasPrefix(real, "/usr/bin/") || strings.HasPrefix(real, "/Applications/Xcode.app/") || strings.HasPrefix(real, "/Library/Developer/"):
				mgr = "apple"
			}
			mu.Lock()
			rows = append(rows, map[string]string{"name": s.name, "version": v, "path": p, "manager": mgr})
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	return rows, nil
}

func brewPackages() ([]map[string]string, error) {
	out, ok := sh("brew", "list", "--versions")
	if !ok {
		return nil, nil
	}
	var rows []map[string]string
	for l := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			rows = append(rows, map[string]string{"name": f[0], "version": normalizeBrewVersion(f[len(f)-1])})
		}
	}
	return rows, nil
}

func nodeInstalls() ([]map[string]string, error) {
	var rows []map[string]string
	nvmDir := os.Getenv("NVM_DIR")
	if nvmDir == "" {
		nvmDir = filepath.Join(home(), ".nvm")
	}
	def, _ := os.ReadFile(filepath.Join(nvmDir, "alias", "default"))
	if ents, err := os.ReadDir(filepath.Join(nvmDir, "versions", "node")); err == nil {
		for _, e := range ents {
			v := strings.TrimPrefix(e.Name(), "v")
			isDef := "false"
			if d := strings.TrimSpace(string(def)); d == v || d == "v"+v || d == major(v) {
				isDef = "true"
			}
			rows = append(rows, map[string]string{"manager": "nvm", "version": v, "major": major(v),
				"path": filepath.Join(nvmDir, "versions", "node", e.Name(), "bin", "node"), "default": isDef})
		}
	}
	if out, ok := sh("fnm", "ls"); ok {
		for _, m := range regexp.MustCompile(`v(\d+\.\d+\.\d+)`).FindAllStringSubmatch(out, -1) {
			rows = append(rows, map[string]string{"manager": "fnm", "version": m[1], "major": major(m[1]), "path": "", "default": "false"})
		}
	}
	if out, ok := sh("volta", "list", "node", "--format", "plain"); ok {
		if m := regexp.MustCompile(`node@(\d+\.\d+\.\d+)`).FindStringSubmatch(out); m != nil {
			rows = append(rows, map[string]string{"manager": "volta", "version": m[1], "major": major(m[1]), "path": "", "default": "true"})
		}
	}
	if out, ok := sh("brew", "list", "--versions", "node"); ok {
		if f := strings.Fields(out); len(f) >= 2 {
			rows = append(rows, map[string]string{"manager": "brew", "version": f[1], "major": major(f[1]), "path": "", "default": "false"})
		}
	}
	// superseded: a higher version of the same major is installed under the same manager, so
	// the fix for this row is to remove it, not to install beside it again.
	for _, r := range rows {
		r["superseded"] = "false"
		for _, o := range rows {
			if o["manager"] == r["manager"] && o["major"] == r["major"] && version.Less(r["version"], o["version"]) {
				r["superseded"] = "true"
				break
			}
		}
	}
	return rows, nil
}

func pyInfo(kind, py string) map[string]string {
	row := map[string]string{"kind": kind, "path": py, "version": "", "ssl": "false", "certifi": "", "pip": ""}
	if out, ok := sh(py, "-c", "import sys; print('%d.%d.%d' % sys.version_info[:3])"); ok {
		row["version"] = out
	}
	if _, ok := sh(py, "-c", "import ssl"); ok {
		row["ssl"] = "true"
	}
	if out, ok := sh(py, "-c", "import certifi; print(certifi.__version__)"); ok {
		row["certifi"] = firstVersion(out)
	}
	if out, ok := sh(py, "-m", "pip", "--version"); ok {
		row["pip"] = firstVersion(out)
	}
	return row
}

func pythonInstalls() ([]map[string]string, error) {
	var rows []map[string]string
	var mu sync.Mutex
	var wg sync.WaitGroup
	add := func(kind, py string) {
		wg.Go(func() {
			r := pyInfo(kind, py)
			mu.Lock()
			rows = append(rows, r)
			mu.Unlock()
		})
	}
	if out, ok := sh("pyenv", "versions", "--bare"); ok {
		root, _ := sh("pyenv", "root")
		for v := range strings.SplitSeq(out, "\n") {
			if v = strings.TrimSpace(v); v != "" {
				if p := filepath.Join(root, "versions", v, "bin", "python"); fileExists(p) {
					add("pyenv", p)
				}
			}
		}
	}
	if out, ok := sh("brew", "list", "--formula"); ok {
		for f := range strings.SplitSeq(out, "\n") {
			if strings.HasPrefix(f, "python@") {
				prefix, _ := sh("brew", "--prefix", f)
				if p := filepath.Join(prefix, "bin", "python3"); fileExists(p) {
					add("brew:"+f, p)
				}
			}
		}
	}
	if p := "/usr/bin/python3"; fileExists(p) {
		add("apple", p)
	}
	if out, ok := sh("conda", "run", "-n", "base", "python", "-c", "import sys; print(sys.executable)"); ok {
		add("conda", strings.TrimSpace(out))
	}
	wg.Wait()
	return rows, nil
}

var defaultVenvRoots = []string{"source", "src", "code", "dev", "projects", "work", "repos", "git"}

func venvs(roots []string) []map[string]string {
	if len(roots) == 0 {
		for _, r := range defaultVenvRoots {
			roots = append(roots, filepath.Join(home(), r))
		}
	}
	var cfgs []string
	for _, root := range roots {
		if !fileExists(root) {
			continue
		}
		base := strings.Count(root, "/")
		// the callback never returns an error, so WalkDir cannot either
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // an unreadable entry is skipped, not fatal
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == ".git" || strings.Count(p, "/")-base > 6 {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Name() == "pyvenv.cfg" {
				cfgs = append(cfgs, p)
			}
			return nil
		})
	}
	var rows []map[string]string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, c := range cfgs {
		py := filepath.Join(filepath.Dir(c), "bin", "python")
		if !fileExists(py) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(py string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := pyInfo("venv", py)
			mu.Lock()
			rows = append(rows, r)
			mu.Unlock()
		}(py)
	}
	wg.Wait()
	return rows
}

func jdkAliases() ([]map[string]string, error) {
	out, ok := sh("keytool", "-list", "-cacerts", "-storepass", "changeit")
	if !ok {
		return nil, nil
	}
	var rows []map[string]string
	for l := range strings.SplitSeq(out, "\n") {
		if i := strings.Index(l, ","); i > 0 && strings.Contains(l, "trustedCertEntry") {
			rows = append(rows, map[string]string{"alias": strings.TrimSpace(l[:i]), "keystore": "cacerts"})
		}
	}
	return rows, nil
}

func electronApps() ([]map[string]string, error) {
	if runtime.GOOS != "darwin" {
		return nil, nil
	}
	var rows []map[string]string
	for _, dir := range []string{"/Applications", filepath.Join(home(), "Applications")} {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".app") {
				continue
			}
			app := filepath.Join(dir, e.Name())
			for _, pl := range []string{
				filepath.Join(app, "Contents/Frameworks/Electron Framework.framework/Resources/Info.plist"),
				filepath.Join(app, "Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"),
			} {
				if !fileExists(pl) {
					continue
				}
				if v, ok := sh("plutil", "-extract", "CFBundleShortVersionString", "raw", pl); ok && v != "" {
					rows = append(rows, map[string]string{"app": strings.TrimSuffix(e.Name(), ".app"), "version": v, "major": major(v), "path": app})
				}
				break
			}
		}
	}
	return rows, nil
}

func caBundles() ([]map[string]string, error) { return nil, nil } // filled by bundleScan (needs options)

// bundleScan reads the well-known trust bundles and reports which bad root names each contains.
func bundleScan(bad []string) []map[string]string {
	cands := map[string]string{
		"/etc/ssl/cert.pem":                          "apple",
		"/opt/homebrew/etc/ca-certificates/cert.pem": "brew",
		"/usr/local/etc/ca-certificates/cert.pem":    "brew",
		"/etc/ssl/certs/ca-certificates.crt":         "distro",
	}
	for _, py := range []string{"python3"} {
		if out, ok := sh(py, "-c", "import certifi; print(certifi.where())"); ok {
			cands[out] = "certifi:" + py
		}
	}
	var rows []map[string]string
	for p, owner := range cands {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var hits []string
		for _, r := range bad {
			if bytes.Contains(b, []byte(r)) {
				hits = append(hits, r)
			}
		}
		rows = append(rows, map[string]string{"path": p, "owner": owner, "bad_roots": strings.Join(hits, ";")})
	}
	return rows
}

func phpIni() ([]map[string]string, error) {
	out, ok := sh("php", "--ini")
	if !ok {
		return nil, nil
	}
	var rows []map[string]string
	re := regexp.MustCompile(`/[^\s,]+\.ini`)
	seen := map[string]bool{}
	for _, p := range re.FindAllString(out, -1) {
		if seen[p] {
			continue
		}
		seen[p] = true
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		enabled := "false"
		sc := bufio.NewScanner(f)
		on := regexp.MustCompile(`^\s*session\.upload_progress\.enabled\s*=\s*(1|On|on|true|True)\b`)
		for sc.Scan() {
			if on.MatchString(sc.Text()) {
				enabled = "true"
			}
		}
		_ = f.Close() // read-only handle
		rows = append(rows, map[string]string{"path": p, "upload_progress_enabled": enabled})
	}
	return rows, nil
}

var dateVer = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(_\d+)?$`)

// normalizeBrewVersion turns Homebrew's date-style versions ("2026-09-25_1") into dotted
// numerics ("2026.09.25.1") so they compare against a pack table.
func normalizeBrewVersion(v string) string {
	if dateVer.MatchString(v) {
		return strings.NewReplacer("-", ".", "_", ".").Replace(v)
	}
	return v
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
