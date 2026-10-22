---
name: php2shell-remediation
description: Find and fix exposure to PHP2Shell (CVE-2026-109618/109619, unauthenticated RCE in PHP ≥ 5.4, patched 2026-10-21) across local repositories and a GitHub org. Use when someone asks to check repos, Dockerfiles, CI, composer files or WordPress installs for vulnerable PHP, to open PHP2Shell remediation PRs, or to confirm a deployment runs a fixed PHP (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).
---

# PHP2Shell remediation

Everything incident-specific is in `packs/php2shell-2026-10/pack.yaml` (fixed versions, EOL
lines, detectors, fixes, probes). This skill is the agent brief. Do not put version numbers
in this file; edit the pack and re-run.

## Scan (deterministic, read-only, seconds)

```bash
fumigator scan --pack php2shell-2026-10 --out findings [--org GITHUB_ORG] ~/source ~/work
```

Read `findings/php2shell-2026-10/summary.md` first, then the per-repo JSON. A repo with
only `info` findings needs nothing. `findings/orphans.txt` lists risk files outside any repo
(installs, backups): check by hand, nothing to PR. With `--org`, `org-missing.txt` lists repos
with no local checkout; `fumigator gh sync --org ORG DEST` clones them, then re-scan.

What the states mean for this pack:

- `vulnerable` (critical): a pinned PHP below the fixed patch. Fix is a text rewrite.
- `eol` (critical): PHP ≤ 8.1, or a composer constraint that allows it. No fix exists from
  php.net; the repo needs a line upgrade decision. Always manual.
- `floating` (critical): `php:8.4` with no patch; a cached layer can hide an old build. Fix pins it.
- `present` on `wordpress-image` / `php-ini-upload-progress`: see the finding note.

## Fix (per repo, needs judgement)

```bash
fumigator fix --pack php2shell-2026-10 --findings findings                       # dry run, every repo
fumigator fix --pack php2shell-2026-10 --findings findings --apply --run-tools --pr --only <repo>
```

Dry-run everything first to see the blast radius. Then one agent per repo (batch 4 to 6),
with this brief:

> Repo `<path>`, findings `findings/php2shell-2026-10/<name>.json`.
> 1. The tree must have no modified tracked files and be on the default branch, or stop and
>    report. `fumigator fix` refuses a dirty tree on its own, but check before you start.
> 2. Dry-run with `--only <name>` and read the plan.
> 3. Run again with `--apply --run-tools`. This creates or reuses branch `sec/php2shell-2026-10`,
>    applies the `rewrite` edits, and runs lockfile tools on PATH. A tool that is missing or
>    fails becomes a MANUAL item with the command; it is never a hard failure.
> 4. For each MANUAL item decide: a service that can move to 8.3 gets the change and a sentence
>    in the PR; one that can't gets the checklist line and, if it can't update today,
>    `session.upload_progress.enabled = 0` in php.ini or the FPM pool with every worker
>    restarted (php.net says this is incomplete; only the update is). WordPress core stays a
>    checklist item with the fixed version.
> 5. Re-scan the repo; only deliberate `manual` items may remain. If there is a Dockerfile and
>    Docker is available, `docker build --pull --no-cache` and run `php -v` inside.
> 6. Run again with `--pr`. With no `origin` or no `gh` auth it commits locally and writes the
>    body to `.git/PR_BODY.md`; push and open by hand. If you hand-edited in step 4, regenerate
>    the body with `--body-only pr-body.md --only <name>` and add a line per edit.
> 7. Report: PR URL, what you changed beyond the automatic edits, what you left for a human,
>    and anything the scanner got wrong (we fix the pack, not the finding).

The orchestrator reads `findings/php2shell-2026-10/fix-log.md` (one section per repo and a
summary table) and gives the user repo → PR → remaining manual items.

## Verify

`php -v` on the host must show a fixed version. For an image: build with `--pull --no-cache`
and run `php -v` inside it. The pack's `verify` block lists the probes.
