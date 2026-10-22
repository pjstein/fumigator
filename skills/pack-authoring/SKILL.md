---
name: pack-authoring
description: Write a new fumigator pack when a security advisory lands (a CA compromise, a runtime RCE, a package that embeds bad roots, a vulnerable base image). Use when someone pastes an advisory and asks to scan repos for it, when a fixed version is published or changes, or when a detector in an existing pack is wrong. Produces packs/<id>/pack.yaml with a fixture and expected.json so `fumigator pack test` passes.
---

# Writing a pack

A pack is the whole incident as data. The engine has four detector types and five fix kinds;
if the incident needs a fifth type, add it to `internal/engine` with a fixture, then write the
pack. The format is documented with examples in `docs/ARCHITECTURE.md` and the two shipped
packs are the reference. Read both before writing.

## Steps

1. **Name it** `<thing>-<yyyy>-<mm>`: `php2shell-2026-10`, `emudhra-ca-2026-10`. One pack per
   vulnerability, even when two land the same week. A repo with only one exposure gets a PR
   about only that one.
2. **Fill the header** from the advisory: `title`, `advisory` URL, `published`, `updated`
   (today), and `summary`: two sentences a reviewer who has not read the advisory can act on.
3. **Versions tables.** One table per runtime or package, keyed by line (`"8.3": "8.3.36"`) or
   `"*"` for a single floor (`certifi: {"*": "2026.10.19"}`). `"pending"` is a legal value and
   produces `unknown` findings until upstream ships. `eol:` lists lines with no fix; any line
   older than the oldest table entry is EOL automatically.
4. **Detectors.** Start from where the exposure lives, not from file types:
   - the runtime binary in a container → `regex-version` over image lines (copy the `files`
     anchor from the eMudhra pack)
   - a version pin a tool reads → `regex-version` over that file
   - a package in a lockfile → `pair` (name line then version line) with a `tool` fix
   - a signature in file bytes → `content` with `$named` string lists; set `max_size`
   - a step that must follow another → `absent` (trigger + require)
   Every detector gets a `severity` per state and a `fix` per state. States you leave out are
   `info` / `manual`, which is the safe default. Use `skip` for tokens that aren't versions
   (`latest`, `stable`), `exclude` for `**/vendor/**` and `**/testdata/**`, and `after:` to
   scope a pattern to lines following a context line (a JSON `"platform": {` block, a YAML
   `with:`).
5. **Fixture.** `packs/<id>/testdata/repo/` holds the smallest files that exercise every
   detector and every state, including one that must *not* fire (a fixed version, a stage that
   already upgrades its bundle). Run `fumigator pack test <id>`; it prints the findings when
   `expected.json` is missing. Read every line, fix the pack, then save the output as
   `testdata/expected.json`. A pack with no fixture is refused.
6. **Parity run.** Scan a real tree (`fumigator scan --pack <id> ~/source`) and read the
   summary. Look for a detector that fires hundreds of times (a glob too wide, a pattern that
   matches dependency blocks instead of the top-level one) and for a repo you know is exposed
   that is missing.
7. **Verify block.** Each probe is a command and an expectation: `fails: true` (a test host
   that a fixed client must reject) or `version_at_least: <table>`.
8. **Skill.** Copy `skills/php2shell-remediation/SKILL.md`, change the pack id and the
   state explanations. No version numbers in the skill.

## Host checks and collectors

A pack's `host:` block queries the tables `fumigator host --collectors` lists. A check names
a table, filters rows with `where`, and either compares one column against a versions table
or reports matching rows as `present`. Every state gets a `fix`: `command` (run by `--apply`),
`sudo: true` (printed, never run), or `suggest` plus `manual` (a command and the reason, for a
decision the person makes). Prefer a `suggest` over a bare `manual`: the person should get a
command to run, not a sentence.

When the inventory shows something no table covers, add a collector, not a special case in
a check: a new file in `internal/host/collectors/` that implements `table.Collector` and calls
`table.Register` in `init()`. Columns are the contract packs write against, so name them for
what a check will filter on (`manager`, `kind`, `owner`, `superseded`). Shell out to the
tool that owns the facts, return an empty table when it is not installed, and mark the
collector `Slow()` if it walks the disk or touches the network.

## Rules

- A version number lives in exactly one place: the pack's `versions` block.
- Lockfiles are never rewritten; their fix kind is `tool`.
- Anything that changes what software an app runs on (a line upgrade) is `manual`.
- Severity is exposure, not effort.
