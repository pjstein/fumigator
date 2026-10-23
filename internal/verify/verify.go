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

	// Images to build: every Dockerfile the PR touched, plus every Dockerfile whose COPY/ADD
	// inputs include a file the PR changed (a lockfile bump changes the image even when the
	// Dockerfile does not).
	out, _ = exec.Command("gh", "pr", "diff", res.Number, "--repo", res.Repo, "--name-only").Output()
	var changed []string
	for f := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if f != "" {
			changed = append(changed, f)
		}
	}
	if opt.Repo != "" {
		if orig := strings.TrimSpace(gitOut(opt.Repo, "branch", "--show-current")); orig != "" {
			defer func() { _ = exec.Command("git", "-C", opt.Repo, "checkout", "-q", orig).Run() }()
		}
	}
	var dockerfiles []string
	checkoutErr := fmt.Errorf("docker not installed here")
	if _, err := exec.LookPath("docker"); err == nil {
		checkoutErr = checkout(opt.Repo, opt.Branch)
	}
	if checkoutErr == nil {
		dockerfiles = affectedDockerfiles(opt.Repo, changed)
	} else {
		for _, f := range changed {
			if isDockerfile(f) {
				dockerfiles = append(dockerfiles, f)
			}
		}
	}
	if len(dockerfiles) > 0 {
		if checkoutErr != nil {
			for _, df := range dockerfiles {
				res.Steps = append(res.Steps, Step{Item: buildItem(df), Detail: checkoutErr.Error(), Ran: false})
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
					res.Steps = append(res.Steps, probeImage(tag, df, urls)...)
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

func isDockerfile(f string) bool {
	base := strings.ToLower(filepath.Base(f))
	return strings.HasPrefix(base, "dockerfile") || strings.HasSuffix(base, ".dockerfile") || base == "containerfile"
}

func gitOut(repo string, args ...string) string {
	out, _ := exec.Command("git", append([]string{"-C", repo}, args...)...).Output()
	return string(out)
}

var copyLine = regexp.MustCompile(`(?im)^\s*(?:COPY|ADD)\s+(.*)$`)

// affectedDockerfiles returns the Dockerfiles that the change set touches directly or through
// a COPY/ADD source. Sources are resolved against both plausible build contexts (the
// Dockerfile's directory and the repository root), since nothing in the file says which.
func affectedDockerfiles(repo string, changed []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(df string) {
		if !seen[df] {
			seen[df] = true
			out = append(out, df)
		}
	}
	for _, f := range changed {
		if isDockerfile(f) {
			add(f)
		}
	}
	for f := range strings.SplitSeq(strings.TrimSpace(gitOut(repo, "ls-files")), "\n") {
		if f == "" || !isDockerfile(f) || seen[f] {
			continue
		}
		b, err := os.ReadFile(filepath.Join(repo, f))
		if err != nil {
			continue
		}
		for _, m := range copyLine.FindAllStringSubmatch(string(b), -1) {
			args := strings.Fields(m[1])
			var srcs []string
			from := false
			for _, a := range args {
				if strings.HasPrefix(a, "--from=") {
					from = true
				}
				if !strings.HasPrefix(a, "--") {
					srcs = append(srcs, strings.Trim(a, `"[],`))
				}
			}
			if from || len(srcs) < 2 {
				continue
			}
			for _, src := range srcs[:len(srcs)-1] {
				for _, ctx := range []string{filepath.Dir(f), "."} {
					p := filepath.Clean(filepath.Join(ctx, src))
					for _, c := range changed {
						if p == "." || c == p || strings.HasPrefix(c, p+"/") || matchGlob(p, c) {
							add(f)
						}
					}
				}
			}
		}
	}
	return out
}

func matchGlob(pattern, name string) bool {
	if !strings.ContainsAny(pattern, "*?[") {
		return false
	}
	ok, _ := filepath.Match(pattern, name)
	return ok
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

// build runs docker build with the Dockerfile's directory as context and, when that fails on a
// missing path (the usual sign the project builds with the repository root as context),
// once more from the root.
func build(repo, df, tag string, timeout time.Duration) Step {
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	// the build cache from --no-cache --pull builds adds up fast; drop it every time
	defer func() { _ = exec.Command("docker", "builder", "prune", "-af").Run() }()
	st, out := buildIn(repo, df, tag, filepath.Join(repo, filepath.Dir(df)), timeout)
	if !st.Passed && st.Ran && filepath.Dir(df) != "." && contextError(out) {
		st2, _ := buildIn(repo, df, tag, repo, timeout)
		if st2.Passed || !contextError(out) {
			st2.Detail += " (repository root as build context)"
			return st2
		}
	}
	return st
}

func contextError(out string) bool {
	return strings.Contains(out, "failed to compute cache key") || strings.Contains(out, "failed to calculate checksum") || strings.Contains(out, ": not found")
}

func buildIn(repo, df, tag, contextDir string, timeout time.Duration) (Step, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "docker", "build", "--pull", "--no-cache", "-f", filepath.Join(repo, df), "-t", tag, contextDir)
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	start := time.Now()
	err := c.Run()
	st := Step{Item: buildItem(df), Ran: true}
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
			return st, out.String()
		}
		st.Detail = "build failed: " + tail
		return st, out.String()
	}
	st.Passed = true
	st.Detail = fmt.Sprintf("built in %s", time.Since(start).Round(time.Second))
	return st, out.String()
}

// probeScript runs inside the built image. For each test URL it tries every TLS client the
// image has (system curl/wget, Python's default context, certifi, Node, Java), then every CA
// bundle file on disk (certifi, pip's vendored copy, grpc's roots.pem, httplib2, botocore,
// the system bundle) as an explicit trust store. One line per check:
//
//	CHECK <kind> <label> <url> FETCHED|REJECTED
const probeScript = `
ok_fetch() { echo "CHECK $1 $2 $3 FETCHED"; }
ok_reject() { echo "CHECK $1 $2 $3 REJECTED"; }
for u in "$@"; do
  if command -v curl >/dev/null 2>&1; then curl -sSf --max-time 15 -o /dev/null "$u" 2>/dev/null && ok_fetch client curl "$u" || ok_reject client curl "$u";
  elif command -v wget >/dev/null 2>&1; then wget -q -T 15 -O /dev/null "$u" 2>/dev/null && ok_fetch client wget "$u" || ok_reject client wget "$u"; fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import sys,urllib.request; urllib.request.urlopen(sys.argv[1],timeout=15)" "$u" 2>/dev/null && ok_fetch client python3-ssl "$u" || ok_reject client python3-ssl "$u"
    if python3 -c "import certifi" 2>/dev/null; then
      python3 -c "import sys,ssl,certifi,urllib.request; urllib.request.urlopen(sys.argv[1],timeout=15,context=ssl.create_default_context(cafile=certifi.where()))" "$u" 2>/dev/null && ok_fetch client python3-certifi "$u" || ok_reject client python3-certifi "$u"
    fi
  fi
  if command -v node >/dev/null 2>&1; then
    node -e "fetch(process.argv[1]).then(()=>process.exit(0),()=>process.exit(1))" "$u" 2>/dev/null && ok_fetch client node "$u" || ok_reject client node "$u"
  fi
  if command -v java >/dev/null 2>&1; then
    d=$(mktemp -d 2>/dev/null || echo /tmp/fv$$); mkdir -p "$d"
    printf 'public class T{public static void main(String[] a)throws Exception{new java.net.URL(a[0]).openStream().close();}}' > "$d/T.java"
    (cd "$d" && java T.java "$u" >/dev/null 2>&1) && ok_fetch client java "$u" || ok_reject client java "$u"
  fi
done
seen=""
for f in $(find / -xdev -type f \( -name cacert.pem -o -name roots.pem -o -name cacerts.txt -o -name ca-bundle.crt -o -name ca-certificates.crt -o -name tls-ca-bundle.pem -o -name cert.pem \) -size -4096k 2>/dev/null | grep -vE '/(tests?|testdata|fixtures|dummyserver)/' | head -60); do
  h=$(cksum "$f" 2>/dev/null | cut -d' ' -f1-2); case " $seen " in *" $h "*) continue;; esac; seen="$seen $h"
  grep -q 'BEGIN CERTIFICATE' "$f" 2>/dev/null || continue
  for u in "$@"; do
    if command -v curl >/dev/null 2>&1; then curl -sSf --max-time 15 --cacert "$f" -o /dev/null "$u" 2>/dev/null && ok_fetch bundle "$f" "$u" || ok_reject bundle "$f" "$u";
    elif command -v python3 >/dev/null 2>&1; then python3 -c "import sys,ssl,urllib.request; urllib.request.urlopen(sys.argv[1],timeout=15,context=ssl.create_default_context(cafile=sys.argv[2]))" "$u" "$f" 2>/dev/null && ok_fetch bundle "$f" "$u" || ok_reject bundle "$f" "$u";
    elif command -v wget >/dev/null 2>&1; then wget -q -T 15 --ca-certificate="$f" -O /dev/null "$u" 2>/dev/null && ok_fetch bundle "$f" "$u" || ok_reject bundle "$f" "$u";
    elif grep -q -e 'emSign ECC Root CA - G3' -e 'AAA Certificate Services' "$f"; then ok_fetch bundle "$f" "$u";
    else ok_reject bundle "$f" "$u"; fi
  done
done
echo DONE
`

// pipVendored reports bundles that only pip itself reads (pip's private certifi copy): shown in
// the detail, not counted against the image, because nothing but pip installs uses them.
func pipVendored(path string) bool {
	return strings.Contains(path, "/pip/_vendor/")
}

// probeImage runs probeScript in the image and turns its lines into one checklist step per URL.
// A URL passes when every client and every bundle (other than pip's private copy) rejects it.
func probeImage(tag, df string, urls []string) []Step {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	args := append([]string{"run", "--rm", "--user", "0", "--entrypoint", "sh", tag, "-c", probeScript, "sh"}, urls...)
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	type res struct {
		checked             int
		fetched, pipFetched []string
	}
	per := map[string]*res{}
	for _, u := range urls {
		per[u] = &res{}
	}
	done := false
	for l := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 1 && f[0] == "DONE" {
			done = true
		}
		if len(f) != 5 || f[0] != "CHECK" {
			continue
		}
		r := per[f[3]]
		if r == nil {
			continue
		}
		r.checked++
		if f[4] == "FETCHED" {
			label := f[2]
			if f[1] == "bundle" && pipVendored(f[2]) {
				r.pipFetched = append(r.pipFetched, label)
			} else {
				r.fetched = append(r.fetched, f[1]+" "+label)
			}
		}
	}
	var steps []Step
	for _, u := range urls {
		r := per[u]
		st := Step{Item: fmt.Sprintf("the built image rejects %s (a certificate error is the good outcome)", u)}
		switch {
		case !done && r.checked == 0:
			d := strings.Join(strings.Fields(lastLines(string(out), 3)), " ")
			if err != nil && d == "" {
				d = err.Error()
			}
			st.Detail = "could not probe the image from " + df + " (no shell?): " + d
		case r.checked == 0:
			st.Detail = "no TLS client or CA bundle in the image built from " + df + "; not probed"
		case len(r.fetched) > 0:
			st.Ran = true
			st.Detail = "STILL TRUSTS in " + df + ": " + strings.Join(r.fetched, "; ")
		default:
			st.Ran, st.Passed = true, true
			st.Detail = fmt.Sprintf("rejected by all %d client and bundle checks in %s", r.checked-len(r.pipFetched), df)
		}
		if len(r.pipFetched) > 0 {
			st.Detail += ". pip's own vendored copy still trusts it (" + strings.Join(r.pipFetched, ", ") + "); only pip installs read it, upgrade pip in the image"
		}
		steps = append(steps, st)
	}
	return steps
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
