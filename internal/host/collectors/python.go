package collectors

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pjstein/fumigator/internal/host/table"
)

// pythonInstalls: every interpreter that can carry its own certifi, with the certifi and pip
// versions it would use. kind says who manages it, which decides the fix:
//
//	pyenv, pythonorg, uv, apple   interpreters: pip is upgradable in place (except Apple's)
//	brew                           PEP 668: upgrade the formula
//	conda                          conda update -n <name>
//	venv                           a project venv under the source roots: pip in place
//	uv-tool, pipx                  tool environments: uv tool upgrade / pipx upgrade <name>
type pythonInstalls struct{}

func (pythonInstalls) Name() string { return "python_installs" }
func (pythonInstalls) Columns() []string {
	return []string{"kind", "name", "path", "version", "ssl", "certifi", "pip", "grpcio"}
}
func (pythonInstalls) Doc() string {
	return "Python interpreters (pyenv, Homebrew, python.org, uv, Apple, conda base and envs) and virtualenvs (project venvs, uv tool envs, pipx venvs) with their certifi, pip and grpcio versions"
}
func (pythonInstalls) Platforms() []string { return nil }
func (pythonInstalls) Slow() bool          { return true }

func pyInfo(kind, name, py string) table.Row {
	row := table.Row{"kind": kind, "name": name, "path": py, "version": "", "ssl": "false", "certifi": "", "pip": "", "grpcio": ""}
	if out, ok := table.Sh(py, "-c", "import sys; print('%d.%d.%d' % sys.version_info[:3])"); ok {
		row["version"] = out
	}
	if _, ok := table.Sh(py, "-c", "import ssl"); ok {
		row["ssl"] = "true"
	}
	if out, ok := table.Sh(py, "-c", "import certifi; print(certifi.__version__)"); ok {
		row["certifi"] = table.FirstVersion(out)
	}
	if out, ok := table.Sh(py, "-m", "pip", "--version"); ok {
		row["pip"] = table.FirstVersion(out)
	}
	// grpcio ships its own roots.pem; read the version without importing grpc (slow, native)
	if out, ok := table.Sh(py, "-c", "import importlib.metadata as m; print(m.version('grpcio'))"); ok {
		row["grpcio"] = table.FirstVersion(out)
	}
	return row
}

var defaultVenvRoots = []string{"source", "src", "code", "dev", "projects", "work", "repos", "git"}

func (pythonInstalls) Collect(opt table.Options) ([]table.Row, error) {
	type target struct{ kind, name, py string }
	var targets []target
	add := func(kind, name, py string) {
		if table.IsExec(py) {
			targets = append(targets, target{kind, name, py})
		}
	}
	home := table.Home()

	if out, ok := table.Sh("pyenv", "versions", "--bare"); ok {
		root, _ := table.Sh("pyenv", "root")
		for v := range strings.SplitSeq(out, "\n") {
			if v = strings.TrimSpace(v); v != "" {
				add("pyenv", v, filepath.Join(root, "versions", v, "bin", "python"))
			}
		}
	}
	if out, ok := table.Sh("brew", "list", "--formula"); ok {
		for f := range strings.SplitSeq(out, "\n") {
			if strings.HasPrefix(f, "python@") {
				prefix, _ := table.Sh("brew", "--prefix", f)
				add("brew", f, filepath.Join(prefix, "bin", "python3"))
			}
		}
	}
	// python.org installers
	if ents, err := os.ReadDir("/Library/Frameworks/Python.framework/Versions"); err == nil {
		for _, e := range ents {
			if e.Name() != "Current" {
				add("pythonorg", e.Name(), filepath.Join("/Library/Frameworks/Python.framework/Versions", e.Name(), "bin", "python3"))
			}
		}
	}
	// uv-managed interpreters
	if ents, err := os.ReadDir(filepath.Join(home, ".local", "share", "uv", "python")); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				add("uv", e.Name(), filepath.Join(home, ".local", "share", "uv", "python", e.Name(), "bin", "python3"))
			}
		}
	}
	add("apple", "system", "/usr/bin/python3")
	// conda base and envs
	for _, base := range []string{"miniconda3", "anaconda3", "miniforge3", "mambaforge"} {
		b := filepath.Join(home, base)
		if !table.Exists(b) {
			continue
		}
		add("conda", "base", filepath.Join(b, "bin", "python"))
		if ents, err := os.ReadDir(filepath.Join(b, "envs")); err == nil {
			for _, e := range ents {
				add("conda", e.Name(), filepath.Join(b, "envs", e.Name(), "bin", "python"))
			}
		}
	}
	// tool environments
	if ents, err := os.ReadDir(filepath.Join(home, ".local", "share", "uv", "tools")); err == nil {
		for _, e := range ents {
			add("uv-tool", e.Name(), filepath.Join(home, ".local", "share", "uv", "tools", e.Name(), "bin", "python"))
		}
	}
	for _, d := range []string{filepath.Join(home, ".local", "share", "pipx", "venvs"), filepath.Join(home, ".local", "pipx", "venvs")} {
		if ents, err := os.ReadDir(d); err == nil {
			for _, e := range ents {
				add("pipx", e.Name(), filepath.Join(d, e.Name(), "bin", "python"))
			}
		}
	}
	// project venvs
	roots := opt.VenvRoots
	if len(roots) == 0 {
		for _, r := range defaultVenvRoots {
			roots = append(roots, filepath.Join(home, r))
		}
	}
	for _, root := range roots {
		if !table.Exists(root) {
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
				dir := filepath.Dir(p)
				add("venv", filepath.Base(filepath.Dir(dir))+"/"+filepath.Base(dir), filepath.Join(dir, "bin", "python"))
			}
			return nil
		})
	}

	var rows []table.Row
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t target) {
			defer wg.Done()
			defer func() { <-sem }()
			r := pyInfo(t.kind, t.name, t.py)
			mu.Lock()
			rows = append(rows, r)
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return rows, nil
}

func init() { table.Register(pythonInstalls{}) }
