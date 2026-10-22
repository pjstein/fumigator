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
}

type Edit struct {
	File   string
	Line   int
	Before string
	After  string
	Why    string
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
		if err := gitErr(rep.Repo, "rev-parse", "--verify", "--quiet", opt.Branch); err == nil {
			if err := gitErr(rep.Repo, "checkout", "-q", opt.Branch); err != nil {
				r.res.Refused = "checkout " + opt.Branch + ": " + err.Error()
				return r.res
			}
		} else if err := gitErr(rep.Repo, "checkout", "-q", "-b", opt.Branch); err != nil {
			r.res.Refused = "create branch: " + err.Error()
			return r.res
		}
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
	r.res.Edits = append(r.res.Edits, Edit{f.File, i + 1, old, after, why(f)})
	r.refreshComment(f.File, i, f.Replace, f.FixText)
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
		r.res.Edits = append(r.res.Edits, Edit{rel, j + 1, l, n, "comment named the old pin"})
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
	text := f.FixText + "  # " + r.p.ID + ": " + r.p.Advisory
	if i+1 < len(lines) && lines[i+1] == text {
		return // idempotent re-run
	}
	lines = append(lines[:i+1], append([]string{text}, lines[i+1:]...)...)
	r.files[f.File] = lines
	r.dirty[f.File] = true
	r.res.Edits = append(r.res.Edits, Edit{f.File, i + 2, "", text, why(f)})
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
		cmd := f.FixText
		if cmd == "" {
			r.res.Manual = append(r.res.Manual, f)
			continue
		}
		dir := filepath.Join(r.repo, filepath.Dir(f.File))
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
			continue
		}
		c := exec.Command("sh", "-c", cmd)
		c.Dir = dir
		var out bytes.Buffer
		c.Stdout, c.Stderr = &out, &out
		if err := c.Run(); err != nil {
			tail := strings.Join(strings.Fields(out.String()), " ")
			if len(tail) > 300 {
				tail = tail[len(tail)-300:]
			}
			f.Note = fmt.Sprintf("`%s` failed: %s. %s", cmd, tail, f.Note)
			r.res.Manual = append(r.res.Manual, f)
			continue
		}
		r.res.Tools = append(r.res.Tools, tr)
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
			git(repo, "add", "--", rel)
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
		b.WriteString("\nCo-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>\n")
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
		r.note("nothing to change; no PR")
		return
	}
	// no commits ahead of base: nothing to push, so no PR
	if r.opt.Base != "" && gitErr(repo, "diff", "--quiet", r.opt.Base, "HEAD") == nil {
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
				r.res.PRURL = m
			}
			return
		}
		r.res.Refused = "gh pr create: " + s
		return
	}
	r.res.PRURL = s
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
	if len(res.Manual) > 0 {
		b.WriteString("## Still needs a human (not changed by this PR)\n\n")
		for _, f := range res.Manual {
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
	}
	b.WriteString(VerifySection(p, res))
	b.WriteString("\n🤖 Generated with [Claude Code](https://claude.com/claude-code)\n")
	return b.String()
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
