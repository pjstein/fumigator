---
name: emudhra-ca-remediation
description: Find and fix exposure to the October 2026 eMudhra intermediate-CA compromise (emSign ECC Root CA G3 and the Sectigo AAA cross-sign) across local repositories, a GitHub org, and developer Macs. Use when someone asks which repos, Dockerfiles, lockfiles, CI pins, vendored CA bundles or runtimes (Node, Go, Deno, Python certifi, Rust webpki-roots, Composer ca-bundle, Elixir castore, Electron, Java keystores) still trust the compromised chain, or to open remediation PRs org-wide.
---

# eMudhra CA remediation

Incident data lives in `packs/emudhra-ca-2026-10/pack.yaml`: fixed versions per runtime, EOL
lines, the affected root and intermediate names, detectors, fixes, and the trust-chain probes.
Bun and erlang-certifi were still `pending` on 2026-10-22; check the advisory and edit the pack.

## Scan

```bash
fumigator scan --pack emudhra-ca-2026-10 --out findings [--org GITHUB_ORG] ~/source
```

Read `findings/emudhra-ca-2026-10/summary.md`. Severity is about exposure, not effort:
`critical` is a vendored bundle that trusts the chain outright (no revocation possible);
`high` is a runtime or image that trusts it until rebuilt; `medium` is probably fine after a
rebuild but not provable from the file; `low` is hygiene.

States: `vulnerable` = pinned below the fixed release (rewrite); `floating` = unpinned tag or
minor, a cached layer can satisfy it with an old build (rewrite to pin); `eol` = a line with
no fixed release (manual: Node ≤ 21/23/25, Go < 1.26, Electron < 42); `absent` = a distro or
python `FROM` with no ca-certificates/certifi step in that stage (insert-after); `present` =
a signature hit (vendored bundle, builder-stage bundle copy, Bun, `lts/*` alias).

Lockfile findings are `tool` fixes: never hand-edit a lockfile. The command is in the finding.

## Fix

```bash
fumigator fix --pack emudhra-ca-2026-10 --findings findings                       # dry run
fumigator fix --pack emudhra-ca-2026-10 --findings findings --apply --run-tools --pr --only <repo>
```

Per-repo agent brief is the one in `skills/php2shell-remediation/SKILL.md` with the pack id
changed. Decisions the agent makes, not the tool: moving an app off an EOL Node or Go line,
replacing a vendored bundle (use [curl's](https://curl.se/docs/caextract.html) or stop
vendoring; check `testdata/` paths first), and anything in a `COPY --from=builder` stage.
Lockfile findings are `tool` fixes and run only with `--run-tools`; the command is in the
finding and in the PR checklist when the tool is missing here.

## Developer Macs

```bash
fumigator host --pack emudhra-ca-2026-10            # plan: PLAN / SUDO / TODO per finding, then probes
fumigator host --pack emudhra-ca-2026-10 --apply    # run the non-sudo commands, then probes
fumigator host --pack emudhra-ca-2026-10 --tables   # the raw inventory, for debugging a check
```

SUDO lines are printed with the exact command for the person to run. TODO lines are
decisions (EOL Node lines still pinned by repos, Bun, Electron apps). The report lands in
`findings/emudhra-ca-2026-10/host-<hostname>.json` with every table, finding, action and probe.

## Verify

Both probes must fail (certificate error is the good outcome):

```
https://dv-g3b-emudhra.we-have-a-problem.com/        eMudhra's own root
https://dv-g3b-aaa-emudhra.we-have-a-problem.com/    Sectigo AAA cross-sign
```

Then `curl -sSI https://github.com https://pypi.org >/dev/null && echo fine` to prove you did
not over-block. Image and runtime recipes are in `references/verify.md`.
