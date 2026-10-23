// Package fix applies a repo's findings: text rewrites and insertions on a branch, lockfile
// tool commands, and a PR whose body tables every edit and checklists what a human must decide.
//
// Rules carried over from the Python remediator: never edit a lockfile by hand; a tool that is
// missing or fails becomes a manual item, never a hard failure; refuse a dirty working tree;
// reuse the branch if it exists; never force-push; stage only tracked files plus known lockfiles.
package fix

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/pjstein/fumigator/internal/engine"
	"github.com/pjstein/fumigator/internal/findings"
	"github.com/pjstein/fumigator/internal/pack"
)

type Options struct {
	Apply    bool
	RunTools bool
	PR       bool
	Branch   string // default sec/<pack-id>
	Base     string // default: current branch at apply time
	Draft    bool   // open the PR as a draft
	Trailer  string // optional commit trailer line(s), e.g. "Co-Authored-By: ..."; none by default
}

type Edit struct {
	File     string
	Line     int
	Before   string
	After    string
	Why      string
	Detector string
}

type ToolRun struct {
	Finding findings.Finding
	Command string
	Dir     string
	Err     string // "" when it ran, or was not run (dry run)
}

type Result struct {
	Repo     string
	Branch   string
	Edits    []Edit
	Tools    []ToolRun // commands that ran successfully (apply) or would run (dry run)
	Manual   []findings.Finding
	Skipped  []string
	Refused  string // non-empty when nothing was done because of a precondition
	PRURL    string
	Note     string
	BodyPath string
	// ManualOnly is true when the repo has findings but none the tool can change: no diff,
	// so no PR; the body is still written for an issue.
	ManualOnly bool
}

var lockfiles = map[string]bool{
	"package-lock.json": true, "pnpm-lock.yaml": true, "yarn.lock": true, "Cargo.lock": true,
	"uv.lock": true, "poetry.lock": true, "composer.lock": true, "mix.lock": true, "Pipfile.lock": true,
	"pdm.lock": true, "bun.lock": true,
}

type remediator struct {
	p     *pack.Pack
	repo  string
	opt   Options
	files map[string][]string // rel -> lines (with edits applied)
	dirty map[string]bool
	res   *Result
}

// Run applies (or dry-runs) the findings of one repo report.
func Run(p *pack.Pack, rep *findings.RepoReport, opt Options) *Result {
	if opt.Branch == "" {
		opt.Branch = "sec/" + p.ID
	}
	r := &remediator{p: p, repo: rep.Repo, opt: opt, files: map[string][]string{}, dirty: map[string]bool{},
		res: &Result{Repo: rep.Repo, Branch: opt.Branch}}
	isGit := isGitRepo(rep.Repo)

	if opt.Apply && isGit {
		if out := git(rep.Repo, "status", "--porcelain", "--untracked-files=no"); strings.TrimSpace(out.String()) != "" {
			r.res.Refused = "working tree is dirty"
			return r.res
		}
		if opt.Base == "" {
			opt.Base = strings.TrimSpace(git(rep.Repo, "rev-parse", "--abbrev-ref", "HEAD").String())
			r.opt.Base = opt.Base
		}
		// leave the clone on the branch it started on, so later scans read the default branch
		// (only when everything was committed: uncommitted edits would follow the checkout)
		if orig := strings.TrimSpace(git(rep.Repo, "branch", "--show-current").String()); orig != "" && orig != opt.Branch {
			defer func() {
				if strings.TrimSpace(git(rep.Repo, "status", "--porcelain", "--untracked-files=no").String()) == "" {
					_ = gitErr(rep.Repo, "checkout", "-q", orig)
				} else {
					r.note("left on " + opt.Branch + " with uncommitted edits for review; commit them, or discard them (git checkout -- .) and run again with --apply --pr")
				}
			}()
		}
		if why := syncBranch(rep.Repo, opt.Branch, opt.Base); why != "" {
			r.res.Refused = why
			return r.res
		}
		// Findings came from scanning the default branch; the PR branch may already resolve some
		// of them (by an earlier run, a reviewer, or a hand edit). Act on the branch as it is.
		rep = engine.ScanRepo(p, rep.Repo, engine.Options{})
	}

	// Apply in file order, descending line number, so insertions never shift a later edit.
	fs := append([]findings.Finding(nil), rep.Findings...)
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line > fs[j].Line
	})
	var tools []findings.Finding
	for _, f := range fs {
		if f.Severity == "info" {
			continue // reported by scan, never an edit or a checklist item
		}
		switch f.Fix {
		case "manual":
			r.res.Manual = append(r.res.Manual, f)
		case "none", "":
		case "tool":
			tools = append(tools, f)
		case "rewrite":
			r.rewrite(f)
		case "insert-after":
			r.insertAfter(f)
		default:
			r.res.Skipped = append(r.res.Skipped, fmt.Sprintf("%s:%d %s: unknown fix kind %q", f.File, f.Line, f.Detector, f.Fix))
		}
	}
	if opt.Apply {
		r.flush()
	}
	r.runTools(tools)
	sort.SliceStable(r.res.Manual, func(i, j int) bool {
		a, b := r.res.Manual[i], r.res.Manual[j]
		if findings.SeverityRank[a.Severity] != findings.SeverityRank[b.Severity] {
			return findings.SeverityRank[a.Severity] < findings.SeverityRank[b.Severity]
		}
		return a.File < b.File
	})
	sort.SliceStable(r.res.Edits, func(i, j int) bool {
		if r.res.Edits[i].File != r.res.Edits[j].File {
			return r.res.Edits[i].File < r.res.Edits[j].File
		}
		return r.res.Edits[i].Line < r.res.Edits[j].Line
	})

	if opt.Apply && isGit && opt.PR {
		r.commitAndPR(filepath.Base(rep.Repo))
	}
	return r.res
}

// syncBranch puts the clone on branch, current with whatever is on the remote:
//   - remote branch exists: start from it, fast-forwarding a local copy (a reviewer may have
//     pushed commits); a local branch that has diverged is refused, never force-pushed;
//   - remote branch gone and its PR merged: start fresh from the up-to-date base, so the
//     follow-up PR carries only new changes;
//   - neither: create the branch from the current base.
//
// It returns a refusal reason, or "".
func syncBranch(repo, branch, base string) string {
	remote := strings.TrimSpace(git(repo, "ls-remote", "--heads", "origin", branch).String())
	local := gitErr(repo, "rev-parse", "--verify", "--quiet", branch) == nil
	if remote != "" {
		if err := gitErr(repo, "fetch", "-q", "origin", branch); err != nil {
			return "fetch " + branch + ": " + err.Error()
		}
		if local && gitErr(repo, "merge-base", "--is-ancestor", "FETCH_HEAD", branch) == nil {
			// local already contains the remote: keep it (it may hold commits not yet pushed)
			if err := gitErr(repo, "checkout", "-q", branch); err != nil {
				return "checkout " + branch + ": " + err.Error()
			}
			return ""
		}
		if local && gitErr(repo, "merge-base", "--is-ancestor", branch, "FETCH_HEAD") != nil {
			return "local " + branch + " has diverged from origin; reconcile it by hand"
		}
		if err := gitErr(repo, "checkout", "-q", "-B", branch, "FETCH_HEAD"); err != nil {
			return "checkout " + branch + ": " + err.Error()
		}
		return ""
	}
	if local {
		cmd := exec.Command("gh", "pr", "list", "--head", branch, "--state", "merged", "--json", "number", "-q", ".[0].number")
		cmd.Dir = repo
		merged, _ := cmd.Output()
		if strings.TrimSpace(string(merged)) == "" {
			if err := gitErr(repo, "checkout", "-q", branch); err != nil {
				return "checkout " + branch + ": " + err.Error()
			}
			return ""
		}
	}
	start := base
	if base != "" && gitErr(repo, "fetch", "-q", "origin", base) == nil {
		start = "FETCH_HEAD"
	}
	args := []string{"checkout", "-q", "-B", branch}
	if start != "" {
		args = append(args, start)
	}
	if err := gitErr(repo, args...); err != nil {
		return "create branch: " + err.Error()
	}
	return ""
}

func (r *remediator) lines(rel string) ([]string, bool) {
	if l, ok := r.files[rel]; ok {
		return l, true
	}
	b, err := os.ReadFile(filepath.Join(r.repo, rel))
	if err != nil {
		r.res.Skipped = append(r.res.Skipped, rel+": "+err.Error())
		return nil, false
	}
	l := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	r.files[rel] = l
	return l, true
}

// locate returns the 0-based index of the finding's line, re-finding it by content if the
// stored line number no longer holds the matched text. ok=false when it cannot be found.
func (r *remediator) locate(f findings.Finding) (int, bool) {
	lines, ok := r.lines(f.File)
	if !ok {
		return 0, false
	}
	if f.Line >= 1 && f.Line <= len(lines) && lines[f.Line-1] == f.Match {
		return f.Line - 1, true
	}
	for i, l := range lines {
		if l == f.Match {
			return i, true
		}
	}
	return 0, false
}

func (r *remediator) rewrite(f findings.Finding) {
	i, ok := r.locate(f)
	if !ok {
		if r.alreadyApplied(f) {
			return
		}
		r.res.Skipped = append(r.res.Skipped, fmt.Sprintf("%s:%d %s: matched line not found (file changed since scan)", f.File, f.Line, f.Detector))
		return
	}
	old := r.files[f.File][i]
	if hashPinned(r.files[f.File], i) {
		f.Note = "the requirements file is hash-pinned (--hash lines); regenerate it with the tool that wrote it (uv export, pip-compile --generate-hashes, poetry export) instead of editing the pin. " + f.Note
		f.Fix = "manual"
		r.res.Manual = append(r.res.Manual, f)
		return
	}
	var after string
	if f.FixPattern != "" {
		after = regexp.MustCompile(f.FixPattern).ReplaceAllString(old, f.FixText)
	} else if f.Replace != "" {
		after = strings.Replace(old, f.Replace, f.FixText, 1)
	} else {
		after = f.FixText
	}
	if after == old {
		r.res.Skipped = append(r.res.Skipped, fmt.Sprintf("%s:%d %s: rewrite produced no change", f.File, f.Line, f.Detector))
		return
	}
	// A reference pinned by digest resolves by the digest; a changed tag alone changes nothing.
	// Resolve the new tag's digest from the registry, or leave the edit to a person.
	if m := digestRef.FindStringSubmatch(after); m != nil {
		d, err := resolveDigest(m[1])
		if err != nil {
			f.Note = fmt.Sprintf("the image is pinned by digest and the digest for %s could not be resolved here (%v); update tag and digest together", m[1], err)
			f.Fix = "manual"
			r.res.Manual = append(r.res.Manual, f)
			return
		}
		after = strings.Replace(after, m[2], d, 1)
	}
	r.files[f.File][i] = after
	r.dirty[f.File] = true
	r.res.Edits = append(r.res.Edits, Edit{f.File, i + 1, old, after, why(f), f.Detector})
	r.refreshComment(f.File, i, f.Replace, f.FixText)
}

// hashPinned reports a requirement line that carries --hash options (on the line or on its
// backslash continuations): pip --require-hashes needs an exact == pin there.
func hashPinned(lines []string, i int) bool {
	for j := i; j < len(lines) && j < i+40; j++ {
		if strings.Contains(lines[j], "--hash=") {
			return true
		}
		if !strings.HasSuffix(strings.TrimSpace(lines[j]), "\\") {
			return false
		}
	}
	return false
}

// digestRef matches "name:tag@sha256:..." in a FROM or image: line.
var digestRef = regexp.MustCompile(`([\w./-]+:[\w.+-]+)@(sha256:[0-9a-f]{64})`)

// resolveDigest asks the registry (through docker's buildx tooling) for the manifest digest of
// a tag; it is the same digest `docker pull` prints.
func resolveDigest(ref string) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("docker not installed")
	}
	out, err := exec.Command("docker", "buildx", "imagetools", "inspect", ref, "--format", "{{.Manifest.Digest}}").Output()
	if err != nil {
		return "", fmt.Errorf("docker buildx imagetools inspect %s failed", ref)
	}
	d := strings.TrimSpace(string(out))
	if !strings.HasPrefix(d, "sha256:") || len(d) != 71 {
		return "", fmt.Errorf("unexpected digest %q", d)
	}
	return d, nil
}

var isoDate = regexp.MustCompile(`\b20\d\d-\d\d-\d\d\b`)

// refreshComment updates a comment directly above an edited line that names the old version
// (and, when it also carries a pin date, that date), so the comment does not contradict the
// line it describes.
func (r *remediator) refreshComment(rel string, i int, oldVer, newVer string) {
	if oldVer == "" || newVer == "" || oldVer == newVer {
		return
	}
	lines := r.files[rel]
	for j := i - 1; j >= 0 && j >= i-3; j-- {
		l := lines[j]
		t := strings.TrimSpace(l)
		if !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "//") {
			break
		}
		if !strings.Contains(l, oldVer) {
			continue
		}
		n := strings.Replace(l, oldVer, newVer, 1)
		if isoDate.MatchString(n) {
			n = isoDate.ReplaceAllString(n, time.Now().Format("2006-01-02"))
		}
		lines[j] = n
		r.res.Edits = append(r.res.Edits, Edit{rel, j + 1, l, n, "comment named the old pin", ""})
		return
	}
}

func (r *remediator) alreadyApplied(f findings.Finding) bool {
	lines, _ := r.lines(f.File)
	want := f.FixText
	if f.Replace != "" && f.FixPattern == "" {
		want = strings.Replace(f.Match, f.Replace, f.FixText, 1)
	}
	return slices.Contains(lines, want)
}

func (r *remediator) insertAfter(f findings.Finding) {
	if strings.HasSuffix(f.File, ".yml") || strings.HasSuffix(f.File, ".yaml") {
		f.Note += " (compose/k8s image: fix in that image's Dockerfile)"
		r.res.Manual = append(r.res.Manual, f)
		return
	}
	i, ok := r.locate(f)
	if !ok {
		r.res.Skipped = append(r.res.Skipped, fmt.Sprintf("%s:%d %s: matched line not found", f.File, f.Line, f.Detector))
		return
	}
	lines := r.files[f.File]
	// never split a multi-line instruction: insert after its last continuation line
	for i+1 < len(lines) && strings.HasSuffix(strings.TrimRight(lines[i], " \t"), "\\") {
		i++
	}
	// Provenance goes inline only on RUN, where the shell reads "#" as a comment; ENV, ARG,
	// COPY and the rest have no inline comments, so it goes on its own line above.
	note := "# " + r.p.ID + ": " + r.p.Advisory
	ins := []string{note, f.FixText}
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(f.FixText)), "RUN ") {
		ins = []string{f.FixText + "  " + note}
	}
	if i+len(ins) < len(lines) && slices.Equal(lines[i+1:i+1+len(ins)], ins) {
		return // idempotent re-run
	}
	lines = append(lines[:i+1], append(ins, lines[i+1:]...)...)
	r.files[f.File] = lines
	r.dirty[f.File] = true
	r.res.Edits = append(r.res.Edits, Edit{f.File, i + 1 + len(ins), "", strings.Join(ins, " / "), why(f), f.Detector})
}

func (r *remediator) flush() {
	for rel := range r.dirty {
		p := filepath.Join(r.repo, rel)
		if err := os.WriteFile(p, []byte(strings.Join(r.files[rel], "\n")+"\n"), 0o644); err != nil {
			r.res.Skipped = append(r.res.Skipped, rel+": write: "+err.Error())
		}
	}
}

func (r *remediator) runTools(tools []findings.Finding) {
	seen := map[string]bool{}
	for _, f := range tools {
		if f.FixText == "" {
			r.res.Manual = append(r.res.Manual, f)
			continue
		}
		cmd := commandFor(f.FixText, f.File)
		if cmd == "" {
			f.Note = fmt.Sprintf("no command in the pack owns %s (%s); update it with that project's own tool. %s", filepath.Base(f.File), f.FixText, f.Note)
			r.res.Manual = append(r.res.Manual, f)
			continue
		}
		rel := filepath.Dir(f.File)
		dir := filepath.Join(r.repo, rel)
		key := dir + "\x00" + cmd
		if seen[key] {
			continue
		}
		seen[key] = true
		tr := ToolRun{Finding: f, Command: cmd, Dir: dir}
		if !r.opt.Apply || !r.opt.RunTools {
			if !r.opt.Apply {
				r.res.Tools = append(r.res.Tools, tr)
			} else {
				f.Note = "run: `" + cmd + "`. " + f.Note
				r.res.Manual = append(r.res.Manual, f)
			}
			continue
		}
		if !anyToolOnPath(cmd) {
			f.Note = "tool not installed here; run: `" + cmd + "`. " + f.Note
			r.res.Manual = append(r.res.Manual, f)
			r.undoPinsFor(rel, f)
			continue
		}
		if filepath.Base(f.File) == "poetry.lock" {
			cmd = poetryCommand(cmd, filepath.Join(r.repo, f.File))
			tr.Command = cmd
		}
		orig, _ := os.ReadFile(filepath.Join(r.repo, f.File))
		var runErr error
		if filepath.Base(f.File) == "uv.lock" {
			var ran string
			_, ran, runErr = runUVKeepingRevision(dir, cmd)
			if runErr == nil {
				tr.Command = ran
			}
		} else {
			c := exec.Command("sh", "-c", cmd)
			c.Dir = dir
			var out bytes.Buffer
			c.Stdout, c.Stderr = &out, &out
			if err := c.Run(); err != nil {
				runErr = fmt.Errorf("%s", tailOf(out.String()))
			}
		}
		if runErr == nil {
			// a tool that exits 0 must also have reached the fix: re-scan the lockfile
			after := engine.ScanFiles(r.p, r.repo, []string{f.File}, engine.Options{}, nil)
			for _, g := range after.Findings {
				if g.Detector == f.Detector && packageOf(g.Current) == packageOf(f.Current) && g.State == findings.Vulnerable {
					runErr = fmt.Errorf("it ran, but %s only reached %s (fix: %s); lock restored", packageOf(g.Current), strings.TrimPrefix(g.Current, packageOf(g.Current)+" "), g.Fixed)
					if orig != nil {
						_ = os.WriteFile(filepath.Join(r.repo, f.File), orig, 0o644)
					}
				}
			}
		}
		if runErr != nil {
			f.Note = fmt.Sprintf("`%s` failed: %v. %s", cmd, runErr, f.Note)
			r.res.Manual = append(r.res.Manual, f)
			r.undoPinsFor(rel, f)
			continue
		}
		r.res.Tools = append(r.res.Tools, tr)
	}
}

// undoPinsFor rolls back manifest pins for the finding's package in rel, and says so.
func (r *remediator) undoPinsFor(rel string, f findings.Finding) {
	pkg := packageOf(f.Current)
	for _, e := range r.rollbackPins(rel, pkg) {
		r.res.Skipped = append(r.res.Skipped, fmt.Sprintf("%s:%d reverted the %s pin: the lock in %s could not be regenerated, so the manifest is left matching the lock", e.File, e.Line, pkg, rel))
	}
}

// anyToolOnPath reports whether the first word of any "||"-separated alternative is installed.
func anyToolOnPath(cmd string) bool {
	for alt := range strings.SplitSeq(cmd, "||") {
		w := strings.Fields(strings.TrimSpace(alt))
		if len(w) > 0 {
			if _, err := exec.LookPath(w[0]); err == nil {
				return true
			}
		}
	}
	return false
}

func (r *remediator) commitAndPR(name string) {
	repo := r.repo
	git(repo, "add", "-u")
	for _, e := range r.res.Edits {
		git(repo, "add", "--", e.File)
	}
	// the callback never returns an error, so Walk cannot either
	_ = filepath.Walk(repo, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable entry is skipped, not fatal
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor", "target", ".venv":
				if p != repo {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if lockfiles[info.Name()] {
			rel, _ := filepath.Rel(repo, p)
			// only lockfiles the repository already tracks: a tool that writes a new lockfile
			// beside a different one (uv in a Poetry project) must not slip it into the PR
			if gitErr(repo, "ls-files", "--error-unmatch", "--", rel) == nil {
				git(repo, "add", "--", rel)
			}
		}
		return nil
	})
	if u := strings.TrimSpace(git(repo, "ls-files", "--others", "--exclude-standard").String()); u != "" {
		n := len(strings.Split(u, "\n"))
		r.note(fmt.Sprintf("%d untracked file(s) left out of the commit (e.g. %s); add a .gitignore if a tool created them", n, strings.Split(u, "\n")[0]))
	}
	if gitErr(repo, "diff", "--cached", "--quiet") != nil {
		var b strings.Builder
		// conventional-commit type so commitlint-style gates accept it
		fmt.Fprintf(&b, "fix(security): %s remediation\n\n", r.p.ID)
		for _, e := range r.res.Edits {
			fmt.Fprintf(&b, "- %s:%d: %s -> %s\n", e.File, e.Line, trunc(e.Before, 50), trunc(e.After, 50))
		}
		if t := strings.TrimSpace(r.opt.Trailer); t != "" {
			b.WriteString("\n" + t + "\n")
		}
		if err := gitErr(repo, "commit", "-q", "-m", b.String()); err != nil {
			r.res.Refused = "commit: " + err.Error()
			return
		}
	}
	body := Body(r.p, name, r.res)
	bp := filepath.Join(repo, ".git", "PR_BODY.md")
	if err := os.WriteFile(bp, []byte(body), 0o644); err != nil {
		r.res.Skipped = append(r.res.Skipped, "write PR body: "+err.Error())
	}
	r.res.BodyPath = bp
	if len(r.res.Edits) == 0 && len(r.res.Tools) == 0 && len(r.res.Manual) == 0 {
		// an open PR still gets its checklist and caveats brought up to date
		if url := openPRFor(repo, r.opt.Branch); url != "" {
			r.res.PRURL = url
			r.appendToExistingBody(url)
			r.note("nothing left to change; open PR body refreshed")
			return
		}
		r.note("nothing to change; no PR")
		return
	}
	// no changes against the remote base: nothing to push, so no PR. Compare with the
	// freshly fetched remote base, not the local branch, which may be stale.
	baseRef := r.opt.Base
	if r.opt.Base != "" && gitErr(repo, "fetch", "-q", "origin", r.opt.Base) == nil {
		baseRef = "FETCH_HEAD"
	}
	// "nothing to push" means no commits the base lacks; a branch that is behind or equal to
	// the base has none, whatever its tree looks like
	ahead := strings.TrimSpace(git(repo, "rev-list", "--count", baseRef+"..HEAD").String())
	if r.opt.Base != "" && (ahead == "0" || gitErr(repo, "diff", "--quiet", baseRef, "HEAD") == nil) {
		r.res.ManualOnly = true
		r.note("manual items only, no file changes: no PR; body at " + bp + " for an issue")
		_ = gitErr(repo, "checkout", "-q", r.opt.Base)
		return
	}
	if gitErr(repo, "remote", "get-url", "origin") != nil {
		r.note("no origin remote; committed locally, PR body at " + bp)
		return
	}
	if _, err := exec.LookPath("gh"); err != nil || exec.Command("gh", "auth", "status").Run() != nil {
		r.note("gh missing or not authenticated; committed locally, PR body at " + bp + "; push and open the PR by hand")
		return
	}
	if err := gitErr(repo, "push", "-q", "-u", "origin", r.opt.Branch); err != nil {
		r.res.Refused = "push: " + err.Error()
		return
	}
	title := fmt.Sprintf("fix(security): %s (%s)", r.p.Title, name)
	args := []string{"pr", "create", "--title", title, "--body-file", bp, "--base", r.opt.Base, "--head", r.opt.Branch}
	if r.opt.Draft {
		args = append(args, "--draft")
	}
	c := exec.Command("gh", args...)
	c.Dir = repo
	out, err := c.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		if strings.Contains(s, "already exists") {
			r.note("PR already exists for this branch; pushed update")
			if m := regexp.MustCompile(`https://\S+/pull/\d+`).FindString(s); m != "" {
				r.appendToExistingBody(m)
			}
			if m := regexp.MustCompile(`https://\S+/pull/\d+`).FindString(s); m != "" {
				r.res.PRURL = m
			}
			return
		}
		r.res.Refused = "gh pr create: " + s
		return
	}
	r.res.PRURL = s
}

// openPRFor returns the URL of the open PR whose head is branch in repo, or "".
func openPRFor(repo, branch string) string {
	c := exec.Command("gh", "pr", "list", "--head", branch, "--state", "open", "--json", "url", "-q", ".[0].url")
	c.Dir = repo
	out, err := c.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// appendToExistingBody adds this run's edits and lockfile commands to an open PR's body, so
// its table of changes stays complete when a later pack version adds rules.
func (r *remediator) appendToExistingBody(url string) {
	cur, err := exec.Command("gh", "pr", "view", url, "--json", "body", "-q", ".body").Output()
	if err != nil {
		return
	}
	var b strings.Builder
	if len(r.res.Edits) > 0 || len(r.res.Tools) > 0 {
		fmt.Fprintf(&b, "\n## Additional changes (%s)\n\n", time.Now().Format("2006-01-02"))
	}
	if len(r.res.Edits) > 0 {
		b.WriteString("| File | Line | Before | After | Why |\n|---|---|---|---|---|\n")
		for _, e := range r.res.Edits {
			fmt.Fprintf(&b, "| `%s` | %d | `%s` | `%s` | %s |\n", e.File, e.Line, cell(e.Before), cell(e.After), e.Why)
		}
		b.WriteString("\n")
	}
	for _, t := range r.res.Tools {
		fmt.Fprintf(&b, "- `%s`: `%s` (%s → %s)\n", t.Finding.File, t.Command, t.Finding.Current, t.Finding.Fixed)
	}
	body := string(cur)
	if i := strings.Index(body, "\n## Verify before merging"); i >= 0 {
		body = body[:i] + b.String() + body[i:]
	} else {
		body += b.String()
	}
	body = replaceSection(body, "Known caveats", strings.TrimSuffix(CaveatsSection(r.p, r.res.Edits, r.res.Tools), "\n"))
	// the checklist reflects the current findings: items a newer pack no longer reports go away
	body = replaceSection(body, "Still needs a human (not changed by this PR)", strings.TrimSuffix(ManualSection(r.res.Manual), "\n"))
	tmp, err := os.CreateTemp("", "fumigator-body-*.md")
	if err != nil {
		return
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, _ = tmp.WriteString(body)
	_ = tmp.Close()
	if exec.Command("gh", "pr", "edit", url, "--body-file", tmp.Name()).Run() == nil {
		r.note("PR body extended with this run's changes")
	}
}

// replaceSection swaps the body of "## heading" (up to the next "## " or the footer) for
// content, which is a full section with its heading, or "" to drop it. A missing section is
// added before "## Verify before merging" when content is non-empty.
func replaceSection(body, heading, content string) string {
	re := regexp.MustCompile(`(?s)\n## ` + regexp.QuoteMeta(heading) + `\n.*?(\n## |\n🤖|\z)`)
	if loc := re.FindStringSubmatchIndex(body); loc != nil {
		repl := ""
		if content != "" {
			repl = "\n" + strings.TrimRight(content, "\n") + "\n"
		}
		return body[:loc[0]] + repl + body[loc[2]:]
	}
	if content == "" {
		return body
	}
	if i := strings.Index(body, "\n## Verify before merging"); i >= 0 {
		return body[:i] + "\n" + strings.TrimRight(content, "\n") + "\n" + body[i:]
	}
	return body + "\n" + content
}

// Body renders the PR body: why (from the pack), every edit, lockfiles, the human checklist,
// and the pack's verification probes.
func Body(p *pack.Pack, name string, res *Result) string {
	var b strings.Builder
	b.WriteString("## Why\n\n")
	b.WriteString(strings.TrimSpace(p.Summary))
	fmt.Fprintf(&b, " This PR brings `%s` onto fixed versions.\n\nAdvisory: %s\n\n", name, p.Advisory)
	if len(res.Edits) > 0 {
		b.WriteString("## Changes made\n\n| File | Line | Before | After | Why |\n|---|---|---|---|---|\n")
		for _, e := range res.Edits {
			fmt.Fprintf(&b, "| `%s` | %d | `%s` | `%s` | %s |\n", e.File, e.Line, cell(e.Before), cell(e.After), e.Why)
		}
		b.WriteString("\n")
	}
	if len(res.Tools) > 0 {
		b.WriteString("## Lockfiles regenerated\n\n")
		for _, t := range res.Tools {
			fmt.Fprintf(&b, "- `%s`: `%s` (%s → %s)\n", t.Finding.File, t.Command, t.Finding.Current, t.Finding.Fixed)
		}
		b.WriteString("\n")
	}
	b.WriteString(CaveatsSection(p, res.Edits, res.Tools))
	b.WriteString(ManualSection(res.Manual))
	b.WriteString(VerifySection(p, res))
	b.WriteString("\n🤖 Generated with [Claude Code](https://claude.com/claude-code)\n")
	return b.String()
}

// ManualSection renders "Still needs a human" from the current manual findings; "" when none.
func ManualSection(manual []findings.Finding) string {
	if len(manual) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Still needs a human (not changed by this PR)\n\n")
	for _, f := range manual {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		to := f.Fixed
		if to == "" {
			to = "—"
		}
		fmt.Fprintf(&b, "- [ ] **%s** `%s` — %s (%s): %s → %s. %s\n", f.Severity, loc, f.Detector, f.State, f.Current, to, f.Note)
	}
	b.WriteString("\n")
	return b.String()
}

// CaveatsSection renders the pack's caveats that apply to these edits; "" when none.
func CaveatsSection(p *pack.Pack, edits []Edit, tools []ToolRun) string {
	var out []string
	for _, c := range p.Caveats {
		hit := false
		for _, e := range edits {
			if slices.Contains(c.Detectors, e.Detector) && (c.When == "" || strings.Contains(e.After, c.When)) {
				hit = true
			}
		}
		for _, t := range tools {
			if slices.Contains(c.Detectors, t.Finding.Detector) && (c.When == "" || strings.Contains(t.Finding.Fixed, c.When)) {
				hit = true
			}
		}
		if hit {
			out = append(out, "- "+strings.TrimSpace(c.Text))
		}
	}
	if len(out) == 0 {
		return ""
	}
	return "## Known caveats\n\n" + strings.Join(out, "\n") + "\n\n"
}

// VerifySection renders the "Verify before merging" checklist: CI, a build of each Dockerfile
// the fix touched, and the advisory's test hosts probed from inside the built image.
// `fumigator pr verify` runs these and ticks them.
func VerifySection(p *pack.Pack, res *Result) string {
	var b strings.Builder
	b.WriteString("## Verify before merging\n\n- [ ] CI is green on this branch\n")
	for _, df := range TouchedDockerfiles(res) {
		fmt.Fprintf(&b, "- [ ] `%s` builds with `docker build --pull --no-cache`\n", df)
	}
	if len(TouchedDockerfiles(res)) > 0 {
		for _, u := range ProbeURLs(p) {
			fmt.Fprintf(&b, "- [ ] the built image rejects %s (a certificate error is the good outcome)\n", u)
		}
	}
	return b.String()
}

// TouchedDockerfiles lists the Dockerfiles among the edits, in order.
func TouchedDockerfiles(res *Result) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range res.Edits {
		base := strings.ToLower(filepath.Base(e.File))
		if (strings.HasPrefix(base, "dockerfile") || strings.HasSuffix(base, ".dockerfile") || base == "containerfile") && !seen[e.File] {
			seen[e.File] = true
			out = append(out, e.File)
		}
	}
	return out
}

// ProbeURLs returns the https test hosts from the pack's verify block (probes expected to fail).
func ProbeURLs(p *pack.Pack) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range p.Verify {
		if !v.Expect.Fails {
			continue
		}
		for _, a := range v.Run {
			for _, m := range urlRe.FindAllString(a, -1) {
				if !seen[m] {
					seen[m] = true
					out = append(out, m)
				}
			}
		}
	}
	return out
}

var urlRe = regexp.MustCompile(`https://[\w.-]+/?`)

func (r *remediator) note(s string) {
	if r.res.Note != "" {
		r.res.Note += "; "
	}
	r.res.Note += s
}

func why(f findings.Finding) string {
	s := fmt.Sprintf("%s: %s", f.Detector, f.State)
	if f.Fixed != "" {
		s += " (" + f.Current + " → " + f.Fixed + ")"
	}
	return s
}

func cell(s string) string {
	return strings.ReplaceAll(trunc(strings.TrimSpace(s), 70), "|", "\\|")
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func isGitRepo(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

func git(dir string, args ...string) *bytes.Buffer {
	c := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var out bytes.Buffer
	c.Stdout = &out
	_ = c.Run() // output-only helper; callers that need the status use gitErr
	return &out
}

func gitErr(dir string, args ...string) error {
	c := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var errb bytes.Buffer
	c.Stderr = &errb
	if err := c.Run(); err != nil {
		return fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(errb.String()))
	}
	return nil
}
