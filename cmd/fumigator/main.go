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
	iofs "io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	fumigator "github.com/pjstein/fumigator"
	"github.com/pjstein/fumigator/internal/discover"
	"github.com/pjstein/fumigator/internal/engine"
	"github.com/pjstein/fumigator/internal/findings"
	"github.com/pjstein/fumigator/internal/fix"
	"github.com/pjstein/fumigator/internal/gh"
	"github.com/pjstein/fumigator/internal/host"
	"github.com/pjstein/fumigator/internal/pack"
	"github.com/pjstein/fumigator/internal/verify"
)

// version is set by goreleaser (-X main.version=...).
var version = "dev"

func main() {
	pack.Embedded = fumigator.Packs
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
	case "host":
		err = cmdHost(os.Args[2:])
	case "gh":
		err = cmdGH(os.Args[2:])
	case "pr":
		err = cmdPR(os.Args[2:])
	case "pack":
		err = cmdPack(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "skills":
		err = cmdSkills(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("fumigator", version)
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
  fumigator fix   --pack ID --findings DIR [--apply] [--run-tools] [--pr [--draft]] [--only name,..] [--skip name,..]
                  [--branch NAME] [--base BRANCH] [--body-only PATH --only NAME]
  fumigator host  --pack ID [--pack ID...] [--apply] [--only id,..] [--venv-roots DIR,..] [--out DIR] [--tables]
  fumigator gh    sync --org ORG [--workers N] [--depth N] DEST
  fumigator pr    ready  --pack ID --findings DIR [--no-checks]   un-draft PRs from fix-log.md whose checks all pass
  fumigator pr    probe  --pack ID --image TAG                  probe one built image (every client and CA bundle in it)
  fumigator pr    verify --pack ID --findings DIR [--only name,..] [--ready] [--build-timeout 15m]
                  run each green PR's verify checklist (docker build of touched Dockerfiles, in-image probe) and tick it
  fumigator pack  test [PACK...]
  fumigator pack  lint [PACK...]
  fumigator list
  fumigator skills install [--dir ~/.claude/skills] [--prefix fumigator-]   copy the agent skills out of the binary
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

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	pd := packsDir(fs)
	_ = fs.Parse(args) // ExitOnError: never returns an error
	for _, id := range pack.List(*pd) {
		p, err := pack.Find(*pd, id)
		if err != nil {
			fmt.Printf("%-28s INVALID: %v\n", id, err)
			continue
		}
		where := "embedded"
		if !strings.HasPrefix(p.Dir, "embedded:") {
			where = p.Dir
		}
		fmt.Printf("%-28s %s  (%d detectors, %d host checks, updated %s) [%s]\n", p.ID, p.Title, len(p.Detectors), len(p.Host), p.Updated, where)
	}
}

func cmdSkills(args []string) error {
	if len(args) < 1 || args[0] != "install" {
		return fmt.Errorf("usage: fumigator skills install [--dir DIR]")
	}
	fs := flag.NewFlagSet("skills install", flag.ExitOnError)
	home, _ := os.UserHomeDir()
	dir := fs.String("dir", filepath.Join(home, ".claude", "skills"), "skills directory")
	prefix := fs.String("prefix", "fumigator-", "prefix for each installed skill's directory and name")
	_ = fs.Parse(args[1:]) // ExitOnError
	n := 0
	var names []string
	err := iofs.WalkDir(fumigator.Skills, "skills", func(p string, d iofs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := iofs.ReadFile(fumigator.Skills, p)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(p, "skills/")
		skill, rest, _ := strings.Cut(rel, "/")
		scoped := *prefix + skill
		if rest == "SKILL.md" {
			// the frontmatter name is what the agent lists the skill as; scope it the same way
			b = []byte(strings.Replace(string(b), "\nname: "+skill+"\n", "\nname: "+scoped+"\n", 1))
			names = append(names, scoped)
		}
		dst := filepath.Join(*dir, scoped, rest)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			return err
		}
		n++
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(names)
	fmt.Printf("installed %d files under %s: %s\n", n, *dir, strings.Join(names, ", "))
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
	_ = fs.Parse(args) // ExitOnError
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

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
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
		if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
			return err
		}
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
	draft := fs.Bool("draft", false, "open PRs as drafts")
	trailer := fs.String("trailer", os.Getenv("FUMIGATOR_COMMIT_TRAILER"), "commit trailer line, e.g. \"Co-Authored-By: Name <email>\" (default $FUMIGATOR_COMMIT_TRAILER, else none)")
	only := fs.String("only", "", "comma-separated report names to include")
	skip := fs.String("skip", "", "comma-separated report names to exclude")
	branch := fs.String("branch", "", "branch name (default sec/<pack-id>)")
	base := fs.String("base", "", "PR base branch (default: the branch checked out at apply time)")
	bodyOnly := fs.String("body-only", "", "write the PR body for --only NAME to this path and exit (no git)")
	pd := packsDir(fs)
	_ = fs.Parse(args) // ExitOnError
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
		res := fix.Run(p, rep, fix.Options{Apply: *apply, RunTools: *runTools, PR: *pr, Branch: *branch, Base: *base, Draft: *draft, Trailer: *trailer})
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
		if res.ManualOnly {
			st = "manual only (no PR)"
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
	for s := range strings.SplitSeq(csv, ",") {
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
		fmt.Fprintf(&b, "  changes applied on branch %s; review with git diff, then commit, or discard and run again with --apply --pr\n", res.Branch)
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

func cmdHost(args []string) error {
	fs := flag.NewFlagSet("host", flag.ExitOnError)
	var packs multi
	fs.Var(&packs, "pack", "pack id or directory (repeatable)")
	apply := fs.Bool("apply", false, "run the non-sudo fix commands (default: plan only)")
	only := fs.String("only", "", "comma-separated check ids to include")
	venvRoots := fs.String("venv-roots", "", "comma-separated dirs to search for Python venvs")
	out := fs.String("out", "findings", "output directory for the host report")
	dump := fs.Bool("tables", false, "print the collected tables and exit")
	listC := fs.Bool("collectors", false, "list the collectors (tables, columns, what they hold) and exit")
	fast := fs.Bool("fast", false, "skip slow collectors (OS update check, venv walk, bundle and binary scans)")
	pd := packsDir(fs)
	_ = fs.Parse(args) // ExitOnError
	if *listC {
		for _, c := range host.Collectors() {
			fmt.Printf("%-26s %s\n%-26s columns: %s\n", c.Name(), c.Doc(), "", strings.Join(c.Columns(), ", "))
		}
		return nil
	}
	ps, err := loadPacks(*pd, packs)
	if err != nil {
		return err
	}
	var bad []string
	for _, p := range ps {
		bad = append(bad, p.Strings["bad_roots"]...)
		bad = append(bad, p.Strings["bad_intermediates"]...)
	}
	var roots []string
	if *venvRoots != "" {
		roots = strings.Split(*venvRoots, ",")
	}
	t0 := time.Now()
	tables := host.Collect(host.Options{VenvRoots: roots, BadRoots: bad, Fast: *fast})
	fmt.Fprintf(os.Stderr, "collected %d tables in %.1fs\n", len(tables), time.Since(t0).Seconds())
	if *dump {
		names := make([]string, 0, len(tables))
		for n := range tables {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			t := tables[n]
			fmt.Printf("== %s (%d rows)%s\n", n, len(t.Rows), map[bool]string{true: "  ERROR: " + t.Err, false: ""}[t.Err != ""])
			for _, r := range t.Rows {
				var cells []string
				for _, c := range t.Columns {
					cells = append(cells, c+"="+r[c])
				}
				fmt.Println("  " + strings.Join(cells, "  "))
			}
		}
		return nil
	}
	inc := set(*only)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	for _, p := range ps {
		fmt.Printf("== %s on %s (%s)\n", p.ID, host.Hostname(), map[bool]string{true: "APPLY", false: "plan"}[*apply])
		fs, acts := host.Evaluate(p, tables)
		if len(inc) > 0 {
			var f2 []host.Finding
			var a2 []host.Action
			for i, a := range acts {
				if inc[a.Finding.Detector] {
					f2 = append(f2, fs[i])
					a2 = append(a2, a)
				}
			}
			fs, acts = f2, a2
		}
		var logb strings.Builder
		logf := func(s string) { logb.WriteString(s + "\n") }
		if *apply {
			acts = host.Apply(acts, logf)
		}
		nRun, nManual, nFail := 0, 0, 0
		for _, a := range acts {
			f := a.Finding
			switch {
			case a.Sudo:
				nManual++
			case a.Command == "":
				nManual++
			case a.Err != "":
				nFail++
				fmt.Printf("  FAILED  [%s] %s: %s -> %s\n          $ %s\n          %s\n", f.Severity, f.Detector, f.Current, f.Fixed, a.Command, a.Err)
			case a.Ran:
				nRun++
				fmt.Printf("  RAN     [%s] %s: %s -> %s\n          $ %s\n", f.Severity, f.Detector, f.Current, f.Fixed, a.Command)
			default:
				fmt.Printf("  PLAN    [%s] %s: %s -> %s\n          $ %s\n", f.Severity, f.Detector, f.Current, f.Fixed, a.Command)
			}
		}
		script := host.NeedsYou(p, acts, *apply)
		if script != "" {
			sp := filepath.Join(*out, p.ID, "host-"+host.Hostname()+"-needs-you.sh")
			if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
				return err
			}
			if err := writeAtomic(sp, []byte(script), 0o755); err != nil {
				return err
			}
			fmt.Printf("  -- needs you: commands and reasons (also saved to %s)\n", sp)
			for _, l := range strings.Split(strings.TrimSpace(script), "\n")[3:] {
				fmt.Println("  " + l)
			}
		}
		probes := host.Probe(p)
		if len(probes) > 0 {
			fmt.Println("  -- verify (a fixed client must fail to fetch the test page)")
			for _, pr := range probes {
				if pr.Passed {
					fmt.Printf("  ok      %s\n", pr.ID)
				} else {
					fmt.Printf("  WARN    %s %s\n", pr.ID, pr.Detail)
				}
			}
		}
		rep := host.Report{Pack: p.ID, Host: host.Hostname(), When: time.Now().Format(time.RFC3339), Tables: tables, Findings: fs, Actions: acts, Probes: probes}
		b, _ := json.MarshalIndent(rep, "", " ")
		rp := filepath.Join(*out, p.ID, "host-"+host.Hostname()+".json")
		if err := os.MkdirAll(filepath.Dir(rp), 0o755); err != nil {
			return err
		}
		if err := writeAtomic(rp, b, 0o644); err != nil {
			return err
		}
		if logb.Len() > 0 {
			if err := writeAtomic(filepath.Join(*out, p.ID, "host-"+host.Hostname()+".log"), []byte(logb.String()), 0o644); err != nil {
				return err
			}
		}
		if *apply {
			fmt.Printf("  %d ran, %d failed, %d need you. Report: %s. Open a new terminal before re-running.\n\n", nRun, nFail, nManual, rp)
		} else {
			fmt.Printf("  %d commands planned, %d need you. Re-run with --apply. Report: %s\n\n", len(acts)-nManual, nManual, rp)
		}
	}
	return nil
}

func cmdPR(args []string) error {
	if len(args) >= 1 && args[0] == "verify" {
		return cmdPRVerify(args[1:])
	}
	if len(args) >= 1 && args[0] == "probe" {
		return cmdProbe(args[1:])
	}
	if len(args) < 1 || args[0] != "ready" {
		return fmt.Errorf("usage: fumigator pr ready|verify --pack ID --findings DIR")
	}
	fs := flag.NewFlagSet("pr ready", flag.ExitOnError)
	packRef := fs.String("pack", "", "pack id")
	dir := fs.String("findings", "findings", "findings directory holding <pack>/fix-log.md")
	noChecks := fs.Bool("no-checks", false, "also un-draft PRs in repos that have no CI checks at all")
	_ = fs.Parse(args[1:]) // ExitOnError
	if *packRef == "" {
		return fmt.Errorf("--pack is required")
	}
	urls, err := gh.PRsFromLog(filepath.Join(*dir, *packRef, "fix-log.md"))
	if err != nil {
		return err
	}
	results := make([]gh.PRState, len(urls))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, u string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = gh.Ready(u, *noChecks)
		}(i, u)
	}
	wg.Wait()
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Action]++
		switch r.Action {
		case "ready":
			fmt.Printf("  READY        %s\n", r.URL)
		case "failed":
			fmt.Printf("  FAILED       %s  %s\n", r.URL, r.Err)
		case "left-draft":
			why := "no checks"
			switch {
			case r.Err != "":
				why = r.Err
			case len(r.Failing) > 0:
				why = "failing: " + strings.Join(r.Failing, ", ")
			case len(r.Pending) > 0:
				why = "pending: " + strings.Join(r.Pending, ", ")
			}
			fmt.Printf("  draft        %s  (%s)\n", r.URL, why)
		}
	}
	fmt.Printf("ready now: %d  already ready: %d  left draft: %d  merged: %d  closed: %d  failed: %d\n", counts["ready"], counts["already-ready"], counts["left-draft"], counts["merged"], counts["closed"], counts["failed"])
	return nil
}

// cmdProbe runs the in-image trust probe against an already built image: every TLS client and
// every CA bundle file in it must refuse the pack's test hosts.
func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("pr probe", flag.ExitOnError)
	packRef := fs.String("pack", "", "pack id")
	img := fs.String("image", "", "image tag to probe")
	pd := packsDir(fs)
	_ = fs.Parse(args) // ExitOnError
	if *packRef == "" || *img == "" {
		return fmt.Errorf("usage: fumigator pr probe --pack ID --image TAG")
	}
	p, err := pack.Find(*pd, *packRef)
	if err != nil {
		return err
	}
	failed := false
	for _, st := range verify.ProbeImage(*img, *img, verify.ProbeURLs(p)) {
		mark := "skip"
		switch {
		case st.Ran && st.Passed:
			mark = "pass"
		case st.Ran:
			mark, failed = "FAIL", true
		}
		fmt.Printf("  %-4s %s  (%s)\n", mark, st.Item, st.Detail)
	}
	if failed {
		return fmt.Errorf("%s still trusts the chain", *img)
	}
	return nil
}

func cmdPRVerify(args []string) error {
	fs := flag.NewFlagSet("pr verify", flag.ExitOnError)
	packRef := fs.String("pack", "", "pack id")
	dir := fs.String("findings", "findings", "findings directory holding <pack>/fix-log.md and the per-repo reports")
	only := fs.String("only", "", "comma-separated report names to include")
	ready := fs.Bool("ready", false, "mark a PR ready for review when every step passes")
	timeout := fs.Duration("build-timeout", 15*time.Minute, "per docker build")
	pd := packsDir(fs)
	_ = fs.Parse(args) // ExitOnError
	if *packRef == "" {
		return fmt.Errorf("--pack is required")
	}
	p, err := pack.Find(*pd, *packRef)
	if err != nil {
		return err
	}
	// report name -> local checkout, from the scan reports
	repoDir := map[string]string{}
	reports, _ := filepath.Glob(filepath.Join(*dir, p.ID, "*.json"))
	for _, rp := range reports {
		if rep, err := findings.Read(rp); err == nil {
			repoDir[filepath.Base(rep.Repo)] = rep.Repo
			repoDir[strings.TrimSuffix(filepath.Base(rp), ".json")] = rep.Repo
		}
	}
	urls, err := gh.PRsFromLog(filepath.Join(*dir, p.ID, "fix-log.md"))
	if err != nil {
		return err
	}
	inc := set(*only)
	var log strings.Builder
	fmt.Fprintf(&log, "# verify log — %s — %s\n\n", p.ID, time.Now().Format("2006-01-02 15:04"))
	counts := map[string]int{}
	for _, u := range urls {
		name := filepath.Base(strings.Split(u, "/pull/")[0])
		if len(inc) > 0 && !inc[name] {
			continue
		}
		fmt.Printf("== %s  %s\n", name, u)
		res := verify.Run(p, u, verify.Options{Repo: repoDir[name], BuildTimeout: *timeout, Ready: *ready})
		fmt.Fprintf(&log, "## %s  %s\n\n", name, u)
		for _, st := range res.Steps {
			mark := "skip"
			switch {
			case st.Ran && st.Passed:
				mark = "pass"
			case st.Ran:
				mark = "FAIL"
			}
			fmt.Printf("  %-4s %s  (%s)\n", mark, st.Item, st.Detail)
			fmt.Fprintf(&log, "- %s: %s (%s)\n", mark, st.Item, st.Detail)
		}
		switch {
		case res.Err != "":
			counts["error"]++
			fmt.Printf("  ERROR %s\n", res.Err)
			fmt.Fprintf(&log, "- error: %s\n", res.Err)
		case res.Skipped != "":
			counts["skipped"]++
			fmt.Printf("  skipped: %s\n", res.Skipped)
			fmt.Fprintf(&log, "- skipped: %s\n", res.Skipped)
		case res.AllPassed():
			counts["passed"]++
		default:
			counts["failed"]++
		}
		log.WriteString("\n")
	}
	lp := filepath.Join(*dir, p.ID, "verify-log.md")
	if err := os.WriteFile(lp, []byte(log.String()), 0o644); err != nil {
		return err
	}
	fmt.Printf("passed: %d  failed: %d  skipped: %d  error: %d  log: %s\n", counts["passed"], counts["failed"], counts["skipped"], counts["error"], lp)
	return nil
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
	_ = fs.Parse(args[1:]) // ExitOnError
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
	_ = fs.Parse(args[1:]) // ExitOnError
	refs := fs.Args()
	if len(refs) == 0 {
		refs = pack.List(*pd)
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
	if strings.HasPrefix(p.Dir, "embedded:") {
		return fmt.Errorf("embedded pack has no fixture on disk; run from a checkout")
	}
	td := filepath.Join(p.Dir, "testdata")
	repo := filepath.Join(td, "repo")
	if st, err := os.Stat(repo); err != nil || !st.IsDir() {
		return fmt.Errorf("no testdata/repo fixture")
	}
	var files []string
	if err := filepath.WalkDir(repo, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(repo, path)
			files = append(files, rel)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("walk fixture: %w", err)
	}
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

// writeAtomic replaces path in one rename, so a bash script being executed from the old
// file keeps reading the old inode instead of a half-written new one.
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeLines(path string, lines []string) {
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "fumigator:", err)
	}
}
