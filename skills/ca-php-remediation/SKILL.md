---
name: ca-php-remediation
description: Scan every git repository (and stray installs) under given roots or a GitHub org for exposure to the October 2026 eMudhra intermediate-CA compromise and the PHP2Shell RCEs (CVE-2026-109618/109619), then fix each repo on a branch and open a PR. Use this whenever someone asks to find old or vulnerable Dockerfiles, base images, pinned Node/Go/PHP versions, certifi/webpki-roots/ca-bundle pins, vendored CA bundles, or WordPress/PHP deployments across many repos; to "check all our repos" after a CA or runtime security advisory; or to open remediation PRs org-wide. Also use it for any later CA-compromise or runtime-RCE event — the version table is one JSON file.
---

# CA / PHP remediation across repositories

Two phases, two kinds of agent. Phase 1 is deterministic and cheap: scripts find every repo and
every risky file, and write findings as JSON. Phase 2 is per-repo and needs judgement: an agent
applies the automatic fixes, decides the manual ones, verifies, and opens a PR. Keep them separate
so a bad fix in one repo never stalls discovery, and so the findings log exists even if Phase 2 is
run days later by someone else.

Everything is driven by `scripts/versions.json`. When upstream publishes a new fixed version (Bun and
erlang-certifi were still pending on 2026-10-22), edit that file and re-run; nothing else changes.

## Phase 1 — discover and log (run this yourself, no sub-agents needed)

```bash
scripts/run_all.sh scan --out findings [--org GITHUB_ORG] ~/source ~/work   # any number of roots
```

What it does, in order:

1. `discover.sh` finds every `.git` directory under the roots, then runs **one `rg --files` pass per
   root** for risk-bearing file names (Dockerfiles, compose/k8s manifests, `.nvmrc`, `.tool-versions`,
   `go.mod`, lockfiles, CI workflows, `wp-includes/version.php`, …) and one `rg -l` content pass for
   vendored CA bundles that still carry the affected roots. rg honours `.gitignore`, which is what
   makes this fast on a disk with hundreds of repos; it also means an *uncommitted* `node_modules`
   is skipped on purpose — those are installs, not source. Files outside any repo go to
   `orphans.txt`: they can't get a PR, but they are often the forgotten copies that matter.
2. `scan_repo.py` parses each candidate file and emits findings with `severity`
   (critical/high/medium/low), and `fix` = `auto` (a text edit), `tool` (a lockfile command),
   or `manual` (a human decision, e.g. an EOL Node line with no fixed release).
3. `summary.md` is the log: one row per repo with counts and the worst finding, plus the orphan
   list and, with `--org`, the org repos that have no local checkout.

With `--org`, missing repos are listed; `run_all.sh clone --org ORG DEST` shallow-clones them, then
re-scan. Use `gh auth status` first.

Read `findings/summary.md` and `findings/<repo>.json` before moving on. If a repo has only `info`
findings, skip it. If the summary is empty for a repo you expected to see, check `candidates.txt`:
discovery is name-based, so a Dockerfile called `build.Docker` won't be found — add a glob to
`discover.sh` rather than hand-scanning.

`references/detectors.md` explains each finding kind, why it matters, and known false positives.

## Phase 2 — remediate and open PRs (one sub-agent per repo)

Dry-run first across everything so you can see the blast radius:

```bash
scripts/run_all.sh fix --out findings            # prints WOULD edit / WOULD run / MANUAL per repo
```

Then spawn one agent per repo that has non-info findings (batch 4–6 at a time; they're independent).
Give each agent this brief, filled in:

> Repo: `<path>`. Findings: `<findings/NAME.json>`. Skill scripts: `<skill path>/scripts`.
> 1. `git status` must be clean and you must be on the default branch; if not, stop and report.
> 2. Run `remediate_repo.py <repo> --findings <json>` (dry run) and read the plan.
> 3. Run it again with `--apply --run-tools`. This creates branch `sec/emudhra-php2shell-2026-10`,
>    edits files, and runs lockfile tools that are on PATH (`cargo update`, `uv lock`,
>    `composer update`, `mix deps.update`, `npm install`). A tool that isn't installed, or that fails
>    (no manifest next to the lockfile, network down), becomes a MANUAL item with the command to run;
>    it is never a hard failure. Lockfiles are never hand-edited — a PR with a hand-edited
>    `Cargo.lock` or `uv.lock` fails hash verification and wastes the reviewer's time.
>    The commit stages only tracked files plus known lockfiles; if `npm install` left a
>    `node_modules/` in a repo with no `.gitignore`, it stays out of the commit and is reported.
> 4. For each MANUAL item, decide: if the fix is obvious and safe (bump `.nvmrc` from an EOL Node to
>    the LTS the repo's `package.json` already supports; replace a vendored `cacert.pem` with the
>    current curl bundle the repo clearly just copies), make it and say so. If it changes behaviour
>    (moving PHP 8.1 → 8.3, Node 18 → 24, WordPress core upgrade), leave it as a checklist item in
>    the PR; the PR body already lists it.
> 5. Verify: re-run `scan_repo.py` on the repo — only `tool`/`manual` items you deliberately left
>    should remain. If there is a Dockerfile and Docker is available, `docker build --pull` the
>    primary image and run the trust check in `references/verify.md`. Run the repo's own quick
>    test command if it has one and finishes in under ~5 minutes.
> 6. `remediate_repo.py <repo> --findings <json> --apply --pr` commits, pushes, and opens the PR
>    (it's idempotent on the branch). With no `origin` remote or no authenticated `gh`, it commits
>    locally, writes the body to `.git/PR_BODY.md`, exits 0 and says so; push and open the PR by
>    hand. If you made hand edits in step 4, regenerate the body first so they're in the table:
>    `remediate_repo.py <repo> --findings <json> --body-only pr-body.md`, then add a line for each.
>    Exit codes: 0 = ran (dry run or applied), 2 = refused (dirty tree) or push/PR failed.
> 7. Report back: PR URL, what you changed beyond the automatic edits, what you left for a human,
>    and anything the scanner got wrong (we fix the scanner, not the finding).

Orchestrator: collect every report into `findings/fix-log.md` and give the user a table of
repo → PR → remaining manual items. Repos where the agent stopped (dirty tree, failing build)
go in a separate list with the reason; don't retry them automatically.

## What the fixers change, and what they refuse to

Automatic (`auto`): image tags to the fixed patch (`golang:1.26.4` → `1.26.10`, `php:8.3.30-fpm` →
`8.3.36-fpm`), floating tags pinned (`node:22` → `22.23.4`), `go`/`toolchain` directives, CI
`go-version`/`node-version`/`php-version` pins, `.nvmrc`/`.tool-versions`/`engines.node`/`volta`,
`certifi` pins in requirements files (as a `>=` floor), and a `RUN apk/apt upgrade ca-certificates`
or `RUN pip install -U certifi pip` inserted after a bare `alpine`/`debian`/`ubuntu`/`python` `FROM`.

Tool (`tool`): lockfile regeneration. Never hand-edit a lockfile; if the tool isn't there, it stays
manual.

Manual, always: anything on an EOL line (Node ≤ 21, 23, 25; Go < 1.26; PHP ≤ 8.1), WordPress core,
vendored CA bundles, CA bundles copied from a builder stage, Bun, parameterised `FROM $IMAGE`.
The reason is simple: these change what the software runs on, and a PR that silently moves an app
from PHP 8.1 to 8.3 is worse than a PR that says "this is on 8.1 and PHP2Shell is unpatched there".

The remediator refuses to run on a dirty working tree and never force-pushes. It reuses the branch
if it already exists, so re-running after fixing a scanner bug is safe.

## Why this shape

- **Deterministic discovery, agentic remediation.** Finding a `FROM php:8.1` line doesn't need an
  LLM and shouldn't cost one; deciding whether that service can move to 8.3 does.
- **Findings are a file, not a conversation.** The JSON is the hand-off between phases and the
  audit trail afterwards. Someone can re-run Phase 2 for one repo next week from the same file.
- **One version table.** `versions.json` is the only place a version number lives. For the next
  incident, change the numbers and the detectors still work.
- **PR bodies carry the "why".** Reviewers across the org will see a dozen of these; each body
  explains the incident in two sentences, links the advisories, tables every edit, and checklists
  what's left. `references/pr-template.md` is the model.

## Files

- `scripts/versions.json` — fixed versions, EOL lines, affected root/intermediate names
- `scripts/discover.sh` — repos + candidate files via rg; `--org` compares to GitHub
- `scripts/scan_repo.py` — candidate files → findings JSON
- `scripts/remediate_repo.py` — findings → edits on a branch → PR
- `scripts/run_all.sh` — `scan` / `fix` / `clone` over everything
- `references/detectors.md` — every finding kind, rationale, false positives
- `references/verify.md` — how to prove a built image or runtime no longer trusts the chain
- `references/pr-template.md` — the PR body shape
