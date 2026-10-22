package gh

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// PRState is what `pr ready` found for one pull request.
type PRState struct {
	URL     string
	Repo    string
	Number  string
	Draft   bool
	Checks  int
	Failing []string
	Pending []string
	Action  string // ready | already-ready | left-draft | failed
	Err     string
}

var prURL = regexp.MustCompile(`https://github\.com/([\w.-]+/[\w.-]+)/pull/(\d+)`)

// PRsFromLog extracts the PR URLs recorded in a fix-log.md.
func PRsFromLog(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range prURL.FindAllString(string(b), -1) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Ready marks a PR ready for review when every check passed (or, with allowNoChecks, when
// the repo has no checks at all). Nothing else is changed.
func Ready(url string, allowNoChecks bool) PRState {
	st := PRState{URL: url}
	m := prURL.FindStringSubmatch(url)
	if m == nil {
		st.Action, st.Err = "failed", "not a PR URL"
		return st
	}
	st.Repo, st.Number = m[1], m[2]
	var view struct {
		IsDraft bool `json:"isDraft"`
		State   string
	}
	out, err := exec.Command("gh", "pr", "view", st.Number, "--repo", st.Repo, "--json", "isDraft,state").Output()
	if err != nil {
		st.Action, st.Err = "failed", "gh pr view: "+err.Error()
		return st
	}
	_ = json.Unmarshal(out, &view)
	st.Draft = view.IsDraft
	if view.State != "OPEN" {
		st.Action, st.Err = "left-draft", strings.ToLower(view.State)
		return st
	}
	var checks []struct{ Name, State string }
	out, _ = exec.Command("gh", "pr", "checks", st.Number, "--repo", st.Repo, "--json", "name,state").Output()
	_ = json.Unmarshal(out, &checks)
	st.Checks = len(checks)
	for _, c := range checks {
		switch c.State {
		case "SUCCESS", "SKIPPED", "NEUTRAL":
		case "PENDING", "IN_PROGRESS", "QUEUED", "EXPECTED":
			st.Pending = append(st.Pending, c.Name)
		default:
			st.Failing = append(st.Failing, c.Name)
		}
	}
	if !st.Draft {
		st.Action = "already-ready"
		return st
	}
	if len(st.Failing) > 0 || len(st.Pending) > 0 || (st.Checks == 0 && !allowNoChecks) {
		st.Action = "left-draft"
		return st
	}
	if err := exec.Command("gh", "pr", "ready", st.Number, "--repo", st.Repo).Run(); err != nil {
		st.Action, st.Err = "failed", fmt.Sprintf("gh pr ready: %v", err)
		return st
	}
	st.Action = "ready"
	return st
}
