# Working in fumigator as an agent

fumigator finds and fixes exposure to a named vulnerability on a machine, across local
repositories, and across a GitHub organisation. Read this file, then `README.md`, then
`docs/ARCHITECTURE.md` if you will change code or write a pack.

## The split that matters

- The **binary** does everything deterministic: inventory, matching, version comparison,
  branches, commits, PRs, probes. It is fast and it is the source of truth for what is exposed.
- A **pack** (`packs/<id>/pack.yaml`) holds everything incident-specific. Version numbers
  and patterns live there and nowhere else. If a finding is wrong, fix the pack, not the
  finding.
- A **skill** (`skills/<id>-remediation/SKILL.md`) is the brief for the decisions the binary
  will not make: moving a service off an EOL runtime, replacing a vendored CA bundle,
  anything that changes what software an app runs on.

## Commands you will use

```bash
fumigator list
fumigator host --pack <id> [--apply] [--tables] [--collectors] [--fast]
fumigator scan --pack <id> [--pack <id2>] [--org ORG] --out findings ROOT...
fumigator gh sync --org ORG DEST
fumigator fix --pack <id> --findings findings [--apply] [--run-tools] [--pr --draft] [--only name,..]
fumigator pack lint | test [PACK...]
```

Outputs are files, not conversation: `findings/<pack>/summary.md`, one JSON per repo,
`fix-log.md` (repo to PR), `host-<hostname>.json` (every table, finding, action, probe) and
`host-<hostname>-needs-you.sh` (what a person must run, with reasons). Read those before
reporting.

## Rules

- Dry-run first. `host` and `fix` change nothing without `--apply`; show the plan.
- Never run a `sudo` command or a `suggest` command from the needs-you script on someone's
  behalf without their yes. Those are printed, not run, on purpose.
- Lockfiles are never hand-edited. If a lockfile tool is missing, the finding stays a
  checklist item.
- Commits are `fix(security): <pack-id> remediation`; branches are `sec/<pack-id>`; PRs
  carry the generated body. If a repository's CI gate rejects that shape (a PR template, a
  commit convention), adapt that one PR by hand and say so; do not change the standard for
  everyone.
- A CI failure on a remediation PR is yours only if the diff caused it. Check the same
  workflow on the default branch before concluding.
- Report what you did not run or could not verify, plainly.

## Changing code

- `make test` must pass: golangci-lint (config in `.golangci.yml`), vet, unit tests, and
  every pack's fixture.
- A new host table is a new file in `internal/host/collectors/` implementing
  `table.Collector` and registering in `init()`; columns are the contract packs write against.
- A new repository detector type goes in `internal/engine` with a fixture that exercises it.
- A pack without `testdata/repo` and `expected.json` does not ship. `fumigator pack test <id>`
  prints the current output when `expected.json` is missing; read every line before saving it.

## Writing a pack for a new advisory

Follow `skills/pack-authoring/SKILL.md`. In short: one pack per vulnerability, named
`<thing>-<yyyy>-<mm>`; a two-sentence summary a reviewer can act on; versions tables keyed
by line; detectors that start from where the exposure lives; a host block that queries the
collector tables; a fixture; a parity run on a real tree; a thin skill.
