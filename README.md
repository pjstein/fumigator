# fumigator

Find and fix exposure to a named vulnerability across your machine, every repository on a
disk, and a GitHub organisation. One static binary does the work. One YAML pack per
vulnerability says what to look for and how to fix it. One short skill per vulnerability
briefs an AI coding agent on the decisions the tool leaves to a person.

It was built for the October 2026 eMudhra intermediate-CA compromise and the PHP2Shell RCEs,
and it is shaped for the next incident: when an advisory lands, you write a pack, not a tool.

## Install

Release binaries for macOS and Linux (arm64 and amd64) are on the
[releases page](https://github.com/pjstein/fumigator/releases). The packs and skills are
compiled in, so the binary alone is enough:

```bash
curl -sSfL https://github.com/pjstein/fumigator/releases/latest/download/fumigator_$(uname -s)_$(uname -m).tar.gz | tar xz
sudo mv fumigator /usr/local/bin/
```

Or with Go 1.26 or newer:

```bash
go install github.com/pjstein/fumigator/cmd/fumigator@latest
```

Prerequisites: `git` for repository scans; the GitHub CLI (`gh auth login`) for organisation
sync and pull requests. On macOS the host collectors shell out to whatever managers you have
(Homebrew, nvm, pyenv, uv, conda, keytool, podman) and skip the ones you don't.

## Scan this machine

```bash
fumigator list                                        # packs built in
fumigator host --pack emudhra-ca-2026-10              # plan: what is exposed, what would run
fumigator host --pack emudhra-ca-2026-10 --apply      # run the fixes that need no password
```

`host` inventories the machine as tables (installed runtimes, Node and Python installs,
JDK keystore aliases, Electron apps, CA bundle files, binaries with a compiled-in trust
store, container VMs, ...) and evaluates the pack's checks against them. The output has
three parts:

- commands it will run under `--apply`, each once;
- a "needs you" list: every item it will not run, as a commented bash script with the
  reason above each command (sudo steps, decisions such as removing an EOL runtime, and
  commands that failed), saved to `findings/<pack>/host-<hostname>-needs-you.sh`;
- verification probes: each TLS client on the machine tries the advisory's test host, and a
  client that still succeeds is reported as STILL TRUSTS.

Re-run after acting; items clear as the state changes. `--tables` dumps the raw inventory,
`--collectors` lists the tables and their columns, `--fast` skips the slow collectors.

## Scan repositories and an organisation

```bash
fumigator scan --pack emudhra-ca-2026-10 --pack php2shell-2026-10 --out findings ~/src
fumigator scan --pack emudhra-ca-2026-10 --org my-org --out findings ~/src   # also lists org repos with no checkout
fumigator gh sync --org my-org ~/src/my-org                                   # shallow-clone the missing ones, then re-scan
```

`scan` finds every git repository under the roots, lists each one's files with
`git ls-files` (so `.gitignore` semantics are exactly git's), runs the pack's detectors, and
writes `findings/<pack>/summary.md` plus one JSON per repo. A few hundred repos take seconds.
Files outside any repository that look risky (installs, backups) go to `orphans.txt`.

## Fix and open pull requests

```bash
fumigator fix --pack emudhra-ca-2026-10 --findings findings                       # dry run: WOULD edit / WOULD run / MANUAL
fumigator fix --pack emudhra-ca-2026-10 --findings findings --apply --run-tools --pr --draft --only one-repo
fumigator fix --pack emudhra-ca-2026-10 --findings findings --apply --run-tools --pr --draft
```

Rules: dry run unless `--apply`; refuses a repo with modified tracked files; works on branch
`sec/<pack-id>` and reuses it; never force-pushes; never hand-edits a lockfile (lockfile
fixes are tool commands that run with `--run-tools`, and a tool that is missing or fails
becomes a checklist item); stages tracked files plus known lockfiles only. Commits and PR
titles start `fix(security):`. The PR body is the same everywhere: why, the advisory, a
table of every edit, lockfiles regenerated, a checklist of what a person must decide, and
how to verify. A repo whose findings are all decisions gets the body written to
`.git/PR_BODY.md` and no PR. `findings/<pack>/fix-log.md` maps repo to PR.

```bash
fumigator pr ready --pack emudhra-ca-2026-10 --findings findings [--no-checks]   # un-draft PRs whose checks all pass
```

## Packs

A pack is one YAML file: advisory metadata, fixed-version tables, detectors for repository
files, host checks against the collector tables, fixes, and verification probes. No code.
The two shipped packs are the reference; [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) has
the format and the reasons behind it. To write one for a new advisory, read
`skills/pack-authoring/SKILL.md`, or point your agent at it.

```bash
fumigator pack lint                  # every pack parses and every pattern compiles
fumigator pack test                  # every pack against its fixture repo and expected.json
fumigator scan --pack ./packs/my-new-pack ...   # a directory works anywhere an id does
```

## Agents

The skills under `skills/` are briefs for an AI coding agent (written for Claude Code, plain
Markdown for anything else): which pack to run, what the states mean, which decisions are
the agent's and which are a person's, and how to write the PR. Install them with:

```bash
fumigator skills install            # into ~/.claude/skills, as fumigator-<name> (--prefix to change)
```

[AGENTS.md](AGENTS.md) is the orientation file for an agent working in this repository.

## Layout

```
cmd/fumigator/            CLI
internal/pack             pack format, loader, validation
internal/engine           repository detectors (regex-version, content, pair, absent)
internal/discover         repos and files via git ls-files; orphans
internal/fix              edits, lockfile tools, branch, commit, PR
internal/host             host checks; collectors/ one file per table; table/ the registry
internal/gh               org enumeration and clone/fetch
packs/<id>/               pack.yaml and testdata/{repo,expected.json}
skills/                   agent briefs, one per pack, plus pack-authoring
docs/ARCHITECTURE.md      design, pack format, collector tables
```

## Development

```bash
make build      # bin/fumigator, CGO off, static
make test       # golangci-lint, go vet, go test, pack fixtures
make release    # dist/ binaries for darwin and linux, arm64 and amd64
```

Releases are built by goreleaser on a `v*` tag.

## License

MIT, see [LICENSE](LICENSE).
