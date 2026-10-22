// Package discover finds git repositories under roots and lists their tracked-or-untracked,
// non-ignored files. It shells out to `git ls-files` so .gitignore semantics are exactly git's;
// a hand-written matcher is where every scanner gets this subtly wrong.
package discover

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// SkipDirs are never descended into when looking for repos or orphans.
var SkipDirs = map[string]bool{
	"node_modules": true, ".cache": true, ".venv": true, "venv": true, "site-packages": true,
	"target": true, "dist": true, "build": true, ".Trash": true, "Library": true, ".npm": true,
	".cargo": true, ".rustup": true, ".pyenv": true, ".nvm": true, "go": true,
}

// Repos returns every directory containing .git under the roots, depth-limited.
func Repos(roots []string, maxDepth int) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, root := range roots {
		root, _ = filepath.Abs(root)
		rootDepth := strings.Count(root, string(os.PathSeparator))
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			name := d.Name()
			if p != root && SkipDirs[name] {
				return filepath.SkipDir
			}
			if strings.Count(p, string(os.PathSeparator))-rootDepth > maxDepth {
				return filepath.SkipDir
			}
			if name == ".git" {
				r := filepath.Dir(p)
				if !seen[r] {
					seen[r] = true
					out = append(out, r)
				}
				return filepath.SkipDir
			}
			// a .git *file* marks a worktree or submodule checkout
			if fi, err := os.Stat(filepath.Join(p, ".git")); err == nil && !fi.IsDir() {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// Files lists repo-relative paths git would consider part of the working tree:
// tracked files plus untracked files that are not ignored. Submodule paths are skipped.
func Files(repo string) ([]string, error) {
	cmd := exec.Command("git", "-C", repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, &RepoError{Repo: repo, Err: err, Stderr: strings.TrimSpace(stderr.String())}
	}
	var out []string
	for _, p := range bytes.Split(stdout.Bytes(), []byte{0}) {
		if len(p) == 0 || installDir(string(p)) {
			continue
		}
		out = append(out, string(p))
	}
	return out, nil
}

// installDir reports whether a repo-relative path sits inside a dependency install that git
// happens not to ignore (a repo with no .gitignore after `npm install`). Installs are not
// source; the host and image fixes cover them.
func installDir(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case "node_modules", ".venv", "venv", "site-packages", "__pycache__", ".tox", ".cache":
			return true
		}
	}
	return false
}

type RepoError struct {
	Repo, Stderr string
	Err          error
}

func (e *RepoError) Error() string {
	return e.Repo + ": git ls-files: " + e.Err.Error() + " " + e.Stderr
}

// Orphans walks the roots for files whose names match any of the globs and that are not
// inside any repo. These are installs, vendored copies, and backups: nothing to PR, but
// often the forgotten copy that matters.
func Orphans(roots, repos []string, match func(rel string) bool) []string {
	sort.Slice(repos, func(i, j int) bool { return len(repos[i]) > len(repos[j]) })
	inRepo := func(p string) bool {
		for _, r := range repos {
			if p == r || strings.HasPrefix(p, r+string(os.PathSeparator)) {
				return true
			}
		}
		return false
	}
	var out []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, root := range roots {
		root, _ = filepath.Abs(root)
		wg.Add(1)
		go func(root string) {
			defer wg.Done()
			filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					if p != root && (SkipDirs[d.Name()] || d.Name() == ".git") {
						return filepath.SkipDir
					}
					if inRepo(p) {
						return filepath.SkipDir
					}
					return nil
				}
				rel, _ := filepath.Rel(root, p)
				if match(rel) || match(d.Name()) {
					mu.Lock()
					out = append(out, p)
					mu.Unlock()
				}
				return nil
			})
		}(root)
	}
	wg.Wait()
	sort.Strings(out)
	return out
}

// ReadLines reads a file up to max bytes and returns its lines. Oversized files return ok=false.
func ReadLines(path string, max int64) (lines []string, ok bool, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), int(max)+1)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, true, sc.Err()
}
