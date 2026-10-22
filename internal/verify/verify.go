// Package verify runs the "Verify before merging" checklist of a remediation PR and writes
// the results back into the PR body: CI state, a `docker build --pull --no-cache` of every
// Dockerfile the PR touched, and the advisory's test hosts probed from inside each built
// image. It is idempotent: the "Verification run" section is replaced on every run.
package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pjstein/fumigator/internal/pack"
)

type Options struct {
	Repo         string        // local checkout of the repository
	Branch       string        // PR head branch, fetched and checked out
	BuildTimeout time.Duration // per docker build
	Ready        bool          // mark the PR ready for review when everything passes
}

type Step struct {
	Item   string // the checklist line, without "- [ ] "
	Passed bool
	Detail string
	Ran    bool // false = skipped (no docker, no shell in image, ...)
}

type Result struct {
	URL     string
	Repo    string
	Number  string
	CIGreen bool
	Steps   []Step
	Skipped string // non-empty when nothing ran (CI not green, PR closed, ...)
	Edited  bool
	Err     string
}

func (r *Result) AllPassed() bool {
	if !r.CIGreen {
		return false
	}
	for _, s := range r.Steps {
		if s.Ran && !s.Passed {
			return false
		}
	}
	return true
}

var (
	prURL    = regexp.MustCompile(`https://github\.com/([\w.-]+/[\w.-]+)/pull/(\d+)`)
	runSect  = regexp.MustCompile(`(?s)\n## Verification run.*?(\n## |\n🤖|\z)`)
	taskLine = regexp.MustCompile(`(?m)^- \[[ x]\] (.*)$`)
)

// Run verifies one PR and updates its body.
func Run(p *pack.Pack, url string, opt Options) Result {
	res := Result{URL: url}
	m := prURL.FindStringSubmatch(url)
	if m == nil {
		res.Err = "not a PR URL"
		return res
	}
	res.Repo, res.Number = m[1], m[2]

	var view struct {
		State, Body, HeadRefName, BaseRefName string
		IsDraft                               bool
	}
	out, err := exec.Command("gh", "pr", "view", res.Number, "--repo", res.Repo, "--json", "state,body,headRefName,baseRefName,isDraft").Output()
	if err != nil {
		res.Err = "gh pr view: " + err.Error()
		return res
	}
	_ = json.Unmarshal(out, &view)
	if view.State != "OPEN" {
		res.Skipped = strings.ToLower(view.State)
		return res
	}
	if opt.Branch == "" {
		opt.Branch = view.HeadRefName
	}

	// CI
	var checks []struct{ Name, State string }
	out, _ = exec.Command("gh", "pr", "checks", res.Number, "--repo", res.Repo, "--json", "name,state").Output()
	_ = json.Unmarshal(out, &checks)
	var failing, pending []string
	for _, c := range checks {
		switch c.State {
		case "SUCCESS", "SKIPPED", "NEUTRAL":
		case "PENDING", "IN_PROGRESS", "QUEUED", "EXPECTED":
			pending = append(pending, c.Name)
		default:
			failing = append(failing, c.Name)
		}
	}
	res.CIGreen = len(failing) == 0 && len(pending) == 0
	ciDetail := fmt.Sprintf("%d checks passed", len(checks))
	switch {
	case len(checks) == 0:
		ciDetail = "no CI configured in this repository"
	case len(failing) > 0:
		ciDetail = "failing: " + strings.Join(failing, ", ")
	case len(pending) > 0:
		ciDetail = "pending: " + strings.Join(pending, ", ")
	}
	res.Steps = append(res.Steps, Step{Item: "CI is green on this branch", Passed: res.CIGreen, Detail: ciDetail, Ran: true})
	if !res.CIGreen {
		res.Skipped = "CI not green: " + ciDetail
		return res
	}

	// Dockerfiles the PR touched
	out, _ = exec.Command("gh", "pr", "diff", res.Number, "--repo", res.Repo, "--name-only").Output()
	var dockerfiles []string
	for f := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		base := strings.ToLower(filepath.Base(f))
		if f != "" && (strings.HasPrefix(base, "dockerfile") || strings.HasSuffix(base, ".dockerfile") || base == "containerfile") {
			dockerfiles = append(dockerfiles, f)
		}
	}
	if len(dockerfiles) > 0 {
		if _, err := exec.LookPath("docker"); err != nil {
			for _, df := range dockerfiles {
				res.Steps = append(res.Steps, Step{Item: buildItem(df), Detail: "docker not installed here", Ran: false})
			}
		} else if err := checkout(opt.Repo, opt.Branch); err != nil {
			for _, df := range dockerfiles {
				res.Steps = append(res.Steps, Step{Item: buildItem(df), Detail: "checkout: " + err.Error(), Ran: false})
			}
		} else {
			urls := probeURLs(p)
			for i, df := range dockerfiles {
				tag := fmt.Sprintf("fumigator-verify:%s-%d", res.Number, i)
				st := build(opt.Repo, df, tag, opt.BuildTimeout)
				if st.Ran && !st.Passed && view.BaseRefName != "" {
					// does the same Dockerfile build on the base branch? separates "this PR broke
					// it" from "it was already broken"
					if err := checkout(opt.Repo, view.BaseRefName); err == nil {
						base := build(opt.Repo, df, tag+"-base", opt.BuildTimeout)
						if base.Passed {
							st.Detail += ". Builds on " + view.BaseRefName + ": this PR broke it"
							_ = exec.Command("docker", "rmi", "-f", tag+"-base").Run()
						} else {
							st.Detail += ". Also fails on " + view.BaseRefName + " (pre-existing)"
						}
						_ = checkout(opt.Repo, opt.Branch)
					}
				}
				res.Steps = append(res.Steps, st)
				if st.Ran && st.Passed {
					for _, u := range urls {
						res.Steps = append(res.Steps, probe(tag, df, u))
					}
					_ = exec.Command("docker", "rmi", "-f", tag).Run()
				}
			}
		}
	}

	// write the body: first bring the checklist to the current shape, then tick what passed
	body := updateBody(rewriteChecklist(view.Body, dockerfiles, probeURLs(p)), res)
	tmp, err := os.CreateTemp("", "fumigator-body-*.md")
	if err == nil {
		_, _ = tmp.WriteString(body)
		_ = tmp.Close()
		defer func() { _ = os.Remove(tmp.Name()) }()
		if err := exec.Command("gh", "pr", "edit", res.Number, "--repo", res.Repo, "--body-file", tmp.Name()).Run(); err != nil {
			res.Err = "gh pr edit: " + err.Error()
			return res
		}
		res.Edited = true
	}
	if opt.Ready && view.IsDraft && res.AllPassed() {
		_ = exec.Command("gh", "pr", "ready", res.Number, "--repo", res.Repo).Run()
	}
	return res
}

func buildItem(df string) string {
	return fmt.Sprintf("`%s` builds with `docker build --pull --no-cache`", df)
}

func checkout(repo, branch string) error {
	if repo == "" {
		return fmt.Errorf("no local checkout")
	}
	if out, _ := exec.Command("git", "-C", repo, "status", "--porcelain", "--untracked-files=no").Output(); len(bytes.TrimSpace(out)) > 0 {
		return fmt.Errorf("working tree has modified files")
	}
	if out, err := exec.Command("git", "-C", repo, "fetch", "-q", "origin", branch).CombinedOutput(); err != nil {
		return fmt.Errorf("fetch %s: %s", branch, strings.TrimSpace(string(out)))
	}
	// shallow clones may not keep a remote-tracking ref for a fetched branch; FETCH_HEAD always exists
	if out, err := exec.Command("git", "-C", repo, "checkout", "-q", "-B", branch, "FETCH_HEAD").CombinedOutput(); err != nil {
		return fmt.Errorf("checkout %s: %s", branch, strings.TrimSpace(string(out)))
	}
	return nil
}

func build(repo, df, tag string, timeout time.Duration) Step {
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dir := filepath.Join(repo, filepath.Dir(df))
	c := exec.CommandContext(ctx, "docker", "build", "--pull", "--no-cache", "-f", filepath.Join(repo, df), "-t", tag, dir)
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	start := time.Now()
	err := c.Run()
	st := Step{Item: buildItem(df), Ran: true}
	// the build cache from --no-cache --pull builds adds up fast; drop it every time
	defer func() { _ = exec.Command("docker", "builder", "prune", "-af").Run() }()
	if err != nil {
		tail := strings.Join(strings.Fields(lastLines(out.String(), 6)), " ")
		if len(tail) > 300 {
			tail = tail[len(tail)-300:]
		}
		if ctx.Err() != nil {
			tail = "timed out after " + timeout.String()
		}
		if strings.Contains(out.String(), "no space left on device") {
			// the host ran out of disk: not a verdict on the Dockerfile
			st.Ran = false
			st.Detail = "not run: docker host out of disk (prune and re-run)"
			return st
		}
		st.Detail = "build failed: " + tail
		return st
	}
	st.Passed = true
	st.Detail = fmt.Sprintf("built in %s", time.Since(start).Round(time.Second))
	return st
}

// probe runs the first available TLS client inside the image against url. The image must
// fail to fetch it; a fetch that succeeds means the image still trusts the chain.
func probe(tag, df, url string) Step {
	item := fmt.Sprintf("the built image rejects %s (a certificate error is the good outcome)", url)
	script := `if command -v curl >/dev/null 2>&1; then c=curl; curl -sSf --max-time 15 -o /dev/null "$1" && echo FETCHED || echo REJECTED;
elif command -v wget >/dev/null 2>&1; then c=wget; wget -q --timeout=15 -O /dev/null "$1" && echo FETCHED || echo REJECTED;
elif command -v python3 >/dev/null 2>&1; then c=python3; python3 -c "import urllib.request,sys; urllib.request.urlopen(sys.argv[1],timeout=15)" "$1" 2>/dev/null && echo FETCHED || echo REJECTED;
elif command -v node >/dev/null 2>&1; then c=node; node -e "fetch(process.argv[1]).then(()=>console.log('FETCHED'),()=>console.log('REJECTED'))" "$1";
else echo NOCLIENT; fi; echo "client=$c"`
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "docker", "run", "--rm", "--entrypoint", "sh", tag, "-c", script, "sh", url)
	out, err := c.CombinedOutput()
	s := string(out)
	st := Step{Item: item}
	switch {
	case strings.Contains(s, "REJECTED"):
		st.Ran, st.Passed, st.Detail = true, true, "rejected, "+clientOf(s)+" in "+df
	case strings.Contains(s, "FETCHED"):
		st.Ran, st.Passed, st.Detail = true, false, "STILL TRUSTS: fetched the test page, "+clientOf(s)+" in "+df
	case strings.Contains(s, "NOCLIENT"):
		st.Detail = "no curl/wget/python3/node in the image built from " + df + "; not probed"
	default:
		d := strings.Join(strings.Fields(lastLines(s, 3)), " ")
		if err != nil && d == "" {
			d = err.Error()
		}
		st.Detail = "could not probe the image from " + df + " (no shell?): " + d
	}
	return st
}

func clientOf(s string) string {
	if i := strings.LastIndex(s, "client="); i >= 0 {
		return "via " + strings.TrimSpace(s[i+7:])
	}
	return ""
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func probeURLs(p *pack.Pack) []string {
	urlRe := regexp.MustCompile(`https://[\w.-]+/?`)
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

var verifySect = regexp.MustCompile(`(?s)\n## Verify before merging\n.*?(\n## |\n🤖|\z)`)

// rewriteChecklist replaces the "Verify before merging" section with the current shape
// (CI, each touched Dockerfile, the in-image probes), keeping ticks already present.
func rewriteChecklist(body string, dockerfiles, urls []string) string {
	ticked := map[string]bool{}
	for _, m := range taskLine.FindAllStringSubmatch(body, -1) {
		if strings.HasPrefix(m[0], "- [x]") {
			ticked[strings.TrimSpace(m[1])] = true
		}
	}
	var b strings.Builder
	b.WriteString("\n## Verify before merging\n\n")
	items := []string{"CI is green on this branch"}
	for _, df := range dockerfiles {
		items = append(items, buildItem(df))
	}
	if len(dockerfiles) > 0 {
		for _, u := range urls {
			items = append(items, fmt.Sprintf("the built image rejects %s (a certificate error is the good outcome)", u))
		}
	}
	for _, it := range items {
		if ticked[it] {
			b.WriteString("- [x] " + it + "\n")
		} else {
			b.WriteString("- [ ] " + it + "\n")
		}
	}
	section := b.String()
	if loc := verifySect.FindStringSubmatchIndex(body); loc != nil {
		return body[:loc[0]] + section + body[loc[2]:]
	}
	return body
}

// updateBody ticks the checklist lines that passed and replaces the Verification run section.
func updateBody(body string, res Result) string {
	passed := map[string]bool{}
	for _, s := range res.Steps {
		if s.Ran && s.Passed {
			passed[s.Item] = true
		}
	}
	body = taskLine.ReplaceAllStringFunc(body, func(line string) string {
		item := strings.TrimSpace(line[6:])
		if passed[item] {
			return "- [x] " + item
		}
		return line
	})
	var b strings.Builder
	fmt.Fprintf(&b, "\n## Verification run\n\n%s by `fumigator pr verify`.\n\n", time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	for _, s := range res.Steps {
		mark := "skipped"
		switch {
		case s.Ran && s.Passed:
			mark = "pass"
		case s.Ran:
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "- %s: %s. %s\n", mark, s.Item, s.Detail)
	}
	if res.Skipped != "" {
		fmt.Fprintf(&b, "- not run: %s\n", res.Skipped)
	}
	section := b.String()
	if loc := runSect.FindStringSubmatchIndex(body); loc != nil {
		// keep the delimiter that ended the old section
		return body[:loc[0]] + section + body[loc[2]:]
	}
	if i := strings.Index(body, "\n🤖"); i >= 0 {
		return body[:i] + section + body[i:]
	}
	return body + section
}
