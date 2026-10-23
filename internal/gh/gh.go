// Package gh enumerates a GitHub organisation and keeps local clones current. It shells out
// to the gh CLI for auth and to git for transport; nothing here needs a token in the process.
package gh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type Repo struct {
	Name          string `json:"name"`
	SSHURL        string `json:"sshUrl"`
	URL           string `json:"url"`
	DefaultBranch struct {
		Name string `json:"name"`
	} `json:"defaultBranchRef"`
	IsArchived bool   `json:"isArchived"`
	PushedAt   string `json:"pushedAt"`
}

// List returns the org's non-archived repos via `gh repo list`.
func List(org string, includeArchived bool) ([]Repo, error) {
	// --no-archived combined with --json returns [] on gh 2.102, so archived repos are
	// filtered here instead.
	args := []string{"repo", "list", org, "--limit", "1000", "--json", "name,sshUrl,url,defaultBranchRef,isArchived,pushedAt"}
	cmd := exec.Command("gh", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gh repo list %s: %w: %s", org, err, strings.TrimSpace(errb.String()))
	}
	var all, repos []Repo
	if err := json.Unmarshal(out.Bytes(), &all); err != nil {
		return nil, err
	}
	for _, r := range all {
		if includeArchived || !r.IsArchived {
			repos = append(repos, r)
		}
	}
	return repos, nil
}

// Missing returns org repos with no directory of the same name under any of the local repo paths.
func Missing(repos []Repo, local []string) []Repo {
	have := map[string]bool{}
	for _, l := range local {
		have[strings.ToLower(filepath.Base(l))] = true
	}
	var out []Repo
	for _, r := range repos {
		if !have[strings.ToLower(r.Name)] {
			out = append(out, r)
		}
	}
	return out
}

type SyncResult struct {
	Name   string
	Action string // cloned | fetched | skipped | failed
	Err    error
}

// Sync shallow-clones missing repos into dest and fast-forwards existing ones, with a worker pool.
func Sync(repos []Repo, dest string, workers int, depth int, progress func(SyncResult)) []SyncResult {
	if workers <= 0 {
		workers = 6
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		out := make([]SyncResult, 0, len(repos))
		for _, r := range repos {
			out = append(out, SyncResult{r.Name, "failed", err})
		}
		return out
	}
	jobs := make(chan Repo)
	var mu sync.Mutex
	var results []SyncResult
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Go(func() {
			for r := range jobs {
				res := syncOne(r, dest, depth)
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
				if progress != nil {
					progress(res)
				}
			}
		})
	}
	for _, r := range repos {
		jobs <- r
	}
	close(jobs)
	wg.Wait()
	return results
}

func syncOne(r Repo, dest string, depth int) SyncResult {
	dir := filepath.Join(dest, r.Name)
	if r.DefaultBranch.Name == "" {
		// an empty repository has no default branch and nothing to scan
		return SyncResult{r.Name, "skipped", fmt.Errorf("empty repository")}
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		// existing clone: refuse to touch a dirty tree, otherwise fetch + reset to origin default
		if out, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); len(bytes.TrimSpace(out)) > 0 {
			return SyncResult{r.Name, "skipped", fmt.Errorf("dirty working tree")}
		}
		br := r.DefaultBranch.Name
		if br == "" {
			br = "HEAD"
		}
		if err := run("git", "-C", dir, "fetch", "-q", "--depth", fmt.Sprint(depth), "origin", br); err != nil {
			return SyncResult{r.Name, "failed", err}
		}
		if err := run("git", "-C", dir, "checkout", "-q", "-B", br, "origin/"+br); err != nil {
			return SyncResult{r.Name, "failed", err}
		}
		return SyncResult{r.Name, "fetched", nil}
	}
	if err := run("git", "clone", "-q", "--depth", fmt.Sprint(depth), r.SSHURL, dir); err != nil {
		return SyncResult{r.Name, "failed", err}
	}
	return SyncResult{r.Name, "cloned", nil}
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return nil
}
