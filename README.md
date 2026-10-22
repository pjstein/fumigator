# fumigator

Find and fix exposure to a named vulnerability across every repository on a disk and in a
GitHub org, fast. One static Go binary does the scanning; one YAML pack per vulnerability
says what to look for; one thin Claude Code skill per vulnerability briefs the agent that
applies the fixes and opens the PRs.

```bash
make                                   # builds bin/fumigator
bin/fumigator list                     # packs available
bin/fumigator scan --pack php2shell-2026-10 --pack emudhra-ca-2026-10 --out findings ~/source
bin/fumigator scan --pack emudhra-ca-2026-10 --org my-org --out findings ~/source
bin/fumigator gh sync --org my-org ~/source/my-org      # shallow-clone what's missing, fetch the rest
bin/fumigator fix --pack php2shell-2026-10 --findings findings            # dry run: WOULD edit / WOULD run / MANUAL
bin/fumigator fix --pack php2shell-2026-10 --findings findings --apply --run-tools --pr --only one-repo
bin/fumigator host --pack emudhra-ca-2026-10 --pack php2shell-2026-10            # this machine: plan
bin/fumigator host --pack emudhra-ca-2026-10 --apply                            # run the non-sudo fixes, then probe
bin/fumigator pack test                # every pack against its fixture
```

254 repos, both packs: about 5 seconds on an M-series laptop.

Output under `findings/<pack>/`: `summary.md` (one row per repo with findings) and one JSON
per repo. `findings/orphans.txt` lists risk files outside any repo; `org-missing.txt` lists
org repos with no local checkout.

Design, pack format, and the reasons for not embedding YARA-X, Nuclei or Semgrep are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Writing a new pack: `skills/pack-authoring`.

## Layout

```
cmd/fumigator/        CLI
internal/             engine, pack loader, discovery (git ls-files), findings, gh
packs/<id>/           pack.yaml + testdata/{repo,expected.json}
skills/<id>-remediation/   agent briefs, one per vulnerability
skills/pack-authoring/     how to write the next pack
skills/ca-php-remediation/ previous Python scanner + remediator (superseded; kept for reference)
```

## Status (2026-10-22)

Done: scan, fix (branch, rewrites, insertions, lockfile tools, commit, push, PR), host
(collector tables, pack-driven checks and fixes, verification probes), gh sync, pack
test/lint, two packs with fixtures. Not done: osv-scalibr for lockfiles, a `pack test` for
host checks against recorded tables. `make test` runs golangci-lint (config in
`.golangci.yml`), vet, unit tests and the pack fixtures.

`host` rules: plan only unless `--apply`; a `sudo: true` fix is printed, never run; each
command runs once even when several rows need it; the pack's `verify` probes run after,
and a client that still fetches the test page is reported as STILL TRUSTS.

`fix` rules: dry run unless `--apply`; refuses a repo with modified tracked files; reuses the
`sec/<pack-id>` branch; never force-pushes; never hand-edits a lockfile (a tool that is missing
or fails becomes a checklist item); stages tracked files plus known lockfiles only; with no
`origin` or no `gh` auth it commits locally and leaves the body at `.git/PR_BODY.md`.
