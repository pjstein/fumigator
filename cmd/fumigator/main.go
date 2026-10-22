// fumigator: find and fix exposure to a named vulnerability across local repos and a GitHub org.
//
//	fumigator scan  --pack ID [--pack ID...] [--out DIR] [--org ORG] [--all] ROOT...
//	fumigator gh    sync --org ORG [--workers N] [--depth N] DEST
//	fumigator pack  test [PACK...]        run every pack against packs/<id>/testdata/
//	fumigator pack  lint [PACK...]
//	fumigator list                        packs available
//
// Packs live in ./packs (override with --packs or FUMIGATOR_PACKS).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pjstein/fumigator/internal/discover"
	"github.com/pjstein/fumigator/internal/engine"
	"github.com/pjstein/fumigator/internal/findings"
	"github.com/pjstein/fumigator/internal/fix"
	"github.com/pjstein/fumigator/internal/gh"
	"github.com/pjstein/fumigator/internal/pack"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(os.Args[2:])
	case "fix":
		err = cmdFix(os.Args[2:])
	case "gh":
		err = cmdGH(os.Args[2:])
	case "pack":
		err = cmdPack(os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fumigator:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  fumigator scan  --pack ID [--pack ID...] [--out DIR] [--org ORG] [--all] [--depth N] ROOT...
  fumigator fix   --pack ID --findings DIR [--apply] [--run-tools] [--pr] [--only name,..] [--skip name,..]
                  [--branch NAME] [--base BRANCH] [--body-only PATH --only NAME]
  fumigator gh    sync --org ORG [--workers N] [--depth N] DEST
  fumigator pack  test [PACK...]
  fumigator pack  lint [PACK...]
  fumigator list
`)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func packsDir(fs *flag.FlagSet) *string {
	def := os.Getenv("FUMIGATOR_PACKS")
	if def == "" {
		def = "packs"
		if exe, err := os.Executable(); err == nil {
			// a built binary next to a packs/ dir (repo root) or ../packs (bin/)
			for _, c := range []string{filepath.Join(filepath.Dir(exe), "packs"), filepath.Join(filepath.Dir(exe), "..", "packs")} {
				if st, err := os.Stat(c); err == nil && st.IsDir() {
					def = c
					break
				}
			}
		}
	}
	return fs.String("packs", def, "directory holding packs")
}

func loadPacks(dir string, refs []string) ([]*pack.Pack, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("--pack is required (see: fumigator list)")
	}
	var out []*pack.Pack
	for _, r := range refs {
		p, err := pack.Find(dir, r)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	pd := packsDir(fs)
	fs.Parse(args)
	ents, err := os.ReadDir(*pd)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		p, err := pack.Load(filepath.Join(*pd, e.Name()))
		if err != nil {
			fmt.Printf("%-28s INVALID: %v\n", e.Name(), err)
			continue
		}
		fmt.Printf("%-28s %s  (%d detectors, updated %s)\n", p.ID, p.Title, len(p.Detectors), p.Updated)
	}
	return nil
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var packs multi
	fs.Var(&packs, "pack", "pack id or directory (repeatable)")
	out := fs.String("out", "findings", "output directory")
	org := fs.String("org", "", "GitHub org to compare against")
	all := fs.Bool("all", false, "also record ok findings")
	depth := fs.Int("depth", 6, "max directory depth when looking for repos")
	workers := fs.Int("workers", 8, "repos scanned concurrently")
	pd := packsDir(fs)
	fs.Parse(args)
	roots := fs.Args()
	if len(roots) == 0 {
		return fmt.Errorf("scan needs at least one ROOT")
	}
	ps, err := loadPacks(*pd, packs)
	if err != nil {
		return err
	}
	t0 := time.Now()
	repos, err := discover.Repos(roots, *depth)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "repos: %d (%.1fs)\n", len(repos), time.Since(t0).Seconds())

	matchAny := func(rel string) bool {
		for _, p := range ps {
			if engine.MatchesName(p, filepath.Base(rel)) {
				return true
			}
		}
		return false
	}
	orphans := discover.Orphans(roots, append([]string(nil), repos...), matchAny)

	var orgMissing []string
	if *org != "" {
		rs, err := gh.List(*org, false)
		if err != nil {
			return err
		}
		for _, m := range gh.Missing(rs, repos) {
			orgMissing = append(orgMissing, fmt.Sprintf("%s  <%s>", m.Name, m.URL))
		}
		fmt.Fprintf(os.Stderr, "org %s: %d repos, %d without a local checkout\n", *org, len(rs), len(orgMissing))
	}

	os.MkdirAll(*out, 0o755)
	writeLines(filepath.Join(*out, "repos.txt"), repos)
	writeLines(filepath.Join(*out, "orphans.txt"), orphans)
	if *org != "" {
		writeLines(filepath.Join(*out, "org-missing.txt"), orgMissing)
	}

	names := findings.Names(repos)
	for _, p := range ps {
		reports := make([]*findings.RepoReport, len(repos))
		sem := make(chan struct{}, *workers)
		var wg sync.WaitGroup
		for i, r := range repos {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, r string) {
				defer wg.Done()
				defer func() { <-sem }()
				reports[i] = engine.ScanRepo(p, r, engine.Options{IncludeOK: *all})
				reports[i].Name = names[r]
			}(i, r)
		}
		wg.Wait()
		total := 0
		for _, rep := range reports {
			if rep.Actionable() || len(rep.Errors) > 0 {
				if _, err := rep.Write(*out); err != nil {
					return err
				}
			}
			for _, f := range rep.Findings {
				if f.Severity != "info" {
					total++
				}
			}
		}
		sum := findings.Summary(p.ID, p.Title, reports, orphans, orgMissing)
		sp := filepath.Join(*out, p.ID, "summary.md")
		os.MkdirAll(filepath.Dir(sp), 0o755)
		if err := os.WriteFile(sp, []byte(sum), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s: %d findings across %d repos -> %s\n", p.ID, total, len(repos), sp)
	}
	fmt.Fprintf(os.Stderr, "done in %.1fs\n", time.Since(t0).Seconds())
	return nil
}

func cmdFix(args []string) error {
	fs := flag.NewFlagSet("fix", flag.ExitOnError)
	packRef := fs.String("pack", "", "pack id or directory")
	dir := fs.String("findings", "findings", "findings directory from scan")
	apply := fs.Bool("apply", false, "edit files on a branch (default: dry run)")
	runTools := fs.Bool("run-tools", false, "run lockfile tool commands that are on PATH")
	pr := fs.Bool("pr", false, "commit, push and open a PR (implies --apply)")
	only := fs.String("only", "", "comma-separated report names to include")
	skip := fs.String("skip", "", "comma-separated report names to exclude")
	branch := fs.String("branch", "", "branch name (default sec/<pack-id>)")
	base := fs.String("base", "", "PR base branch (default: the branch checked out at apply time)")
	bodyOnly := fs.String("body-only", "", "write the PR body for --only NAME to this path and exit (no git)")
	pd := packsDir(fs)
	fs.Parse(args)
	if *packRef == "" {
		return fmt.Errorf("--pack is required")
	}
	p, err := pack.Find(*pd, *packRef)
	if err != nil {
		return err
	}
	if *pr {
		*apply = true
	}
	reports, err := filepath.Glob(filepath.Join(*dir, p.ID, "*.json"))
	if err != nil || len(reports) == 0 {
		return fmt.Errorf("no reports under %s/%s; run scan first", *dir, p.ID)
	}
	inc := set(*only)
	exc := set(*skip)
	var log strings.Builder
	fmt.Fprintf(&log, "# fix log — %s — %s\n\n", p.ID, time.Now().Format("2006-01-02 15:04"))
	type row struct {
		name, pr, state string
		manual          int
	}
	var rows []row
	for _, rp := range reports {
		name := strings.TrimSuffix(filepath.Base(rp), ".json")
		if len(inc) > 0 && !inc[name] {
			continue
		}
		if exc[name] {
			continue
		}
		rep, err := findings.Read(rp)
		if err != nil {
			return err
		}
		if _, err := os.Stat(rep.Repo); err != nil {
			fmt.Printf("== %s: %s missing\n", name, rep.Repo)
			continue
		}
		if *bodyOnly != "" {
			res := fix.Run(p, rep, fix.Options{})
			if err := os.WriteFile(*bodyOnly, []byte(fix.Body(p, filepath.Base(rep.Repo), res)), 0o644); err != nil {
				return err
			}
			fmt.Printf("wrote %s\n", *bodyOnly)
			return nil
		}
		fmt.Printf("== %s (%s)\n", name, rep.Repo)
		res := fix.Run(p, rep, fix.Options{Apply: *apply, RunTools: *runTools, PR: *pr, Branch: *branch, Base: *base})
		printResult(res, *apply)
		fmt.Fprintf(&log, "## %s\n\n", name)
		fmt.Fprintf(&log, "%s", describe(res, *apply))
		st := "dry-run"
		if *apply {
			st = "applied"
		}
		if res.Refused != "" {
			st = "refused: " + res.Refused
		}
		rows = append(rows, row{name, res.PRURL, st, len(res.Manual)})
	}
	if *bodyOnly != "" {
		return fmt.Errorf("--body-only needs --only NAME matching one report")
	}
	fmt.Fprintf(&log, "\n## Summary\n\n| Repo | PR | State | Manual items |\n|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&log, "| `%s` | %s | %s | %d |\n", r.name, r.pr, r.state, r.manual)
	}
	lp := filepath.Join(*dir, p.ID, "fix-log.md")
	if err := os.WriteFile(lp, []byte(log.String()), 0o644); err != nil {
		return err
	}
	if !*apply {
		fmt.Println("(dry run — add --apply to edit on a branch, --run-tools for lockfiles, --pr to open PRs)")
	}
	fmt.Println("log:", lp)
	return nil
}

func set(csv string) map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			m[s] = true
		}
	}
	return m
}

func describe(res *fix.Result, applied bool) string {
	var b strings.Builder
	tag := "WOULD"
	if applied {
		tag = "APPLIED"
	}
	if res.Refused != "" {
		fmt.Fprintf(&b, "  REFUSED     %s\n", res.Refused)
		return b.String()
	}
	for _, e := range res.Edits {
		if e.Before == "" {
			fmt.Fprintf(&b, "  %s insert %s:%d\n    + %s\n", tag, e.File, e.Line, e.After)
		} else {
			fmt.Fprintf(&b, "  %s edit   %s:%d\n    - %s\n    + %s\n", tag, e.File, e.Line, e.Before, e.After)
		}
	}
	for _, t := range res.Tools {
		if applied {
			fmt.Fprintf(&b, "  RAN         %s  (%s)\n", t.Command, t.Finding.File)
		} else {
			fmt.Fprintf(&b, "  WOULD run   %s  (in %s)\n", t.Command, filepath.Dir(t.Finding.File))
		}
	}
	for _, f := range res.Manual {
		fmt.Fprintf(&b, "  MANUAL      [%s] %s:%d %s %s -> %s  %s\n", f.Severity, f.File, f.Line, f.Detector, f.Current, f.Fixed, f.Note)
	}
	for _, s := range res.Skipped {
		fmt.Fprintf(&b, "  SKIPPED     %s\n", s)
	}
	if res.PRURL != "" {
		fmt.Fprintf(&b, "  PR          %s\n", res.PRURL)
	}
	if res.Note != "" {
		fmt.Fprintf(&b, "  note: %s\n", res.Note)
	}
	if applied && res.PRURL == "" && res.Refused == "" && len(res.Edits)+len(res.Tools) > 0 && res.Note == "" {
		fmt.Fprintf(&b, "  changes applied on branch %s; review with git diff, then re-run with --pr\n", res.Branch)
	}
	if len(res.Edits)+len(res.Tools)+len(res.Manual)+len(res.Skipped) == 0 && res.Refused == "" {
		b.WriteString("  nothing to do\n")
	}
	return b.String()
}

func printResult(res *fix.Result, applied bool) {
	fmt.Print(describe(res, applied))
	fmt.Println()
}

func cmdGH(args []string) error {
	if len(args) < 1 || args[0] != "sync" {
		return fmt.Errorf("usage: fumigator gh sync --org ORG DEST")
	}
	fs := flag.NewFlagSet("gh sync", flag.ExitOnError)
	org := fs.String("org", "", "GitHub org")
	workers := fs.Int("workers", 6, "parallel clones")
	depth := fs.Int("depth", 50, "clone depth")
	archived := fs.Bool("archived", false, "include archived repos")
	fs.Parse(args[1:])
	if *org == "" || fs.NArg() != 1 {
		return fmt.Errorf("usage: fumigator gh sync --org ORG DEST")
	}
	repos, err := gh.List(*org, *archived)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: %d repos -> %s\n", *org, len(repos), fs.Arg(0))
	counts := map[string]int{}
	var mu sync.Mutex
	res := gh.Sync(repos, fs.Arg(0), *workers, *depth, func(r gh.SyncResult) {
		mu.Lock()
		counts[r.Action]++
		mu.Unlock()
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "  %-8s %s: %v\n", r.Action, r.Name, r.Err)
		} else {
			fmt.Fprintf(os.Stderr, "  %-8s %s\n", r.Action, r.Name)
		}
	})
	_ = res
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(os.Stderr, "%s: %d\n", k, counts[k])
	}
	return nil
}

func cmdPack(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: fumigator pack test|lint [PACK...]")
	}
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	pd := packsDir(fs)
	fs.Parse(args[1:])
	refs := fs.Args()
	if len(refs) == 0 {
		ents, err := os.ReadDir(*pd)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if e.IsDir() {
				refs = append(refs, e.Name())
			}
		}
	}
	failed := 0
	for _, r := range refs {
		p, err := pack.Find(*pd, r)
		if err != nil {
			fmt.Printf("FAIL %s: %v\n", r, err)
			failed++
			continue
		}
		if args[0] == "lint" {
			fmt.Printf("ok   %s (%d detectors)\n", p.ID, len(p.Detectors))
			continue
		}
		if err := testPack(p); err != nil {
			fmt.Printf("FAIL %s: %v\n", p.ID, err)
			failed++
		} else {
			fmt.Printf("ok   %s\n", p.ID)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d pack(s) failed", failed)
	}
	return nil
}

// testPack scans packs/<id>/testdata/repo and compares (detector,file,line,state,current,fixed)
// tuples with testdata/expected.json. Missing expected.json is a failure: a pack with no
// fixture does not ship.
func testPack(p *pack.Pack) error {
	td := filepath.Join(p.Dir, "testdata")
	repo := filepath.Join(td, "repo")
	if st, err := os.Stat(repo); err != nil || !st.IsDir() {
		return fmt.Errorf("no testdata/repo fixture")
	}
	var files []string
	filepath.Walk(repo, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(repo, path)
			files = append(files, rel)
		}
		return nil
	})
	rep := engine.ScanFiles(p, repo, files, engine.Options{}, nil)
	type key struct {
		Detector, File        string
		Line                  int
		State, Current, Fixed string
	}
	got := map[key]bool{}
	var gotList []key
	for _, f := range rep.Findings {
		k := key{f.Detector, filepath.ToSlash(f.File), f.Line, string(f.State), f.Current, f.Fixed}
		got[k] = true
		gotList = append(gotList, k)
	}
	eb, err := os.ReadFile(filepath.Join(td, "expected.json"))
	if err != nil {
		b, _ := json.MarshalIndent(gotList, "", " ")
		return fmt.Errorf("no expected.json; current output:\n%s", b)
	}
	var want []key
	if err := json.Unmarshal(eb, &want); err != nil {
		return fmt.Errorf("expected.json: %w", err)
	}
	var problems []string
	wantSet := map[key]bool{}
	for _, w := range want {
		wantSet[w] = true
		if !got[w] {
			problems = append(problems, fmt.Sprintf("missing: %+v", w))
		}
	}
	for _, g := range gotList {
		if !wantSet[g] {
			problems = append(problems, fmt.Sprintf("unexpected: %+v", g))
		}
	}
	for _, e := range rep.Errors {
		problems = append(problems, "error: "+e)
	}
	if len(problems) > 0 {
		return fmt.Errorf("\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

func writeLines(path string, lines []string) {
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}
