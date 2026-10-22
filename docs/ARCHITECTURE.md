# Fumigator architecture

Status: implemented through step 3 of the migration order, 2026-10-22. The Python skill under
`skills/ca-php-remediation/` is superseded for scan and fix and kept for reference.

## The problem shape

Every incident so far has the same shape, and we expect more of them:

1. An advisory names a vulnerable thing (a CA root, a runtime line, a package) and a fixed version.
2. Exposure lives in developer toolkits and build inputs: Dockerfiles, lockfiles, CI pins,
   version files, vendored bundles, and the developer's own machine.
3. Remediation is a mechanical edit for most hits and a human decision for the rest.
4. The same question must be answered across hundreds of repos (local disk and GitHub org)
   and dozens of laptops, within hours.

What changes per incident is the **signature** (what to look for, which versions are fixed,
what the fix text is). What stays the same is the **machinery** (walk disks fast, enumerate
an org, parse manifests, compare versions, apply edits on a branch, open PRs, verify).

## Shape of the solution

```
fumigator/
  cmd/fumigator/          Go CLI, one static binary per OS/arch
  internal/               engine: walk, match, versions, lockfiles, git, github, patch
  packs/                  one directory per vulnerability (data, not code)
    emudhra-ca-2026-10/pack.yaml
    php2shell-2026-10/pack.yaml
  skills/                 one Claude Code skill per vulnerability, thin: brief + which pack
    emudhra-ca-remediation/SKILL.md
    php2shell-remediation/SKILL.md
    pack-authoring/SKILL.md     how to write a new pack when the next advisory lands
```

**One pack per vulnerability.** A pack is YAML: advisory metadata, a fixed-version table,
detectors, fixes, and verification probes. No code. The eMudhra pack and the PHP2Shell pack are
separate files even though the October response handled them together; a repo that only has a
PHP exposure gets a PR that only talks about PHP.

**One binary.** `fumigator` does the expensive and error-prone work: concurrent gitignore-aware
walking, regex and content matching, version comparison, manifest/lockfile parsing, GitHub org
enumeration and clone, branch + commit + PR, and post-fix probes. Skills call the binary and
read its JSON. Go gives static cross-compiled binaries for macOS/Linux on both architectures,
goroutines for the per-repo fan-out, and startup time that does not matter.

**One skill per vulnerability, all thin.** A skill is the agent brief: which pack to run, what the
agent decides versus what the binary does, how to write the PR. The skill never contains a
version number or a regex.

## Pack format

```yaml
id: php2shell-2026-10
title: PHP2Shell unauthenticated RCE (CVE-2026-109618, CVE-2026-109619)
advisory: https://www.php.net/archive/2026.php#2026-10-21-5
published: 2026-10-21
updated: 2026-10-22

versions:                       # the only place a version number lives
  php: {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
  php_eol: ["5", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1"]
  wordpress: {"6.9": "6.9.5", "7.0": "7.0.6", "7.1": "7.1.2"}

detectors:
  - id: php-image-tag
    type: regex-version          # regex with named captures, compared against a table
    files: ["Dockerfile", "Dockerfile.*", "*.dockerfile", "Containerfile",
            "docker-compose*.y*ml", "compose*.y*ml", ".github/workflows/*.y*ml", "k8s/**/*.y*ml"]
    pattern: '^\s*(?:FROM\s+(?:--platform=\S+\s+)?|image:\s*["'']?)(?P<name>(?:[\w.-]+/)*php):(?P<version>[\w.-]+)'
    table: php                   # version table keyed by major.minor line
    eol: php_eol
    severity: {vulnerable: critical, eol: critical, floating: high}
    fix:
      vulnerable: {kind: rewrite, capture: version, to: "{fixed}"}
      eol: manual
      floating: manual
    note: "php:* images carry the vulnerable interpreter; PHP2Shell is pre-auth."

  - id: wordpress-core
    type: regex-version
    files: ["**/wp-includes/version.php"]
    pattern: '^\s*\$wp_version\s*=\s*[''"](?P<version>[\d.]+)'
    table: wordpress
    severity: {vulnerable: critical}
    fix: {vulnerable: manual}

  - id: php-ini-upload-progress
    type: content                # presence/absence of a signature, YARA-style strings
    files: ["php.ini", "**/php-fpm.d/*.conf", "*.ini"]
    any: ['session.upload_progress.enabled\s*=\s*(1|On|true)']
    severity: medium
    fix: {kind: rewrite, pattern: '(session\.upload_progress\.enabled\s*=\s*)\S+', to: '${1}0'}

verify:                          # probes run after a fix; pass = exit non-zero / no match
  - id: php-version
    run: ["php", "-r", "echo PHP_VERSION;"]
    expect: {version_at_least: php}
```

Detector types are few and fixed; the engine implements them, packs compose them:

| type | what it does | covers today |
|---|---|---|
| `regex-version` | regex with `name`/`version` captures; looks the line up in a table; classifies as ok / vulnerable / eol / floating | image tags, `.nvmrc`, `go.mod`, CI `*-version:`, `engines.node`, `composer.json` `require.php`, `$wp_version` |
| `content` | signature strings/regexes in file bytes, with size cap and path allowlist | vendored CA bundles, `php.ini` mitigations |
| `package` | package name + fixed version against a parsed lockfile/manifest (via osv-scalibr extractors) | certifi, webpki-roots, composer/ca-bundle, castore, electron |
| `absent` | a file matches `files` but none of `require` patterns appear after a trigger line | missing `ca-certificates` upgrade after a bare `FROM alpine` |

Fix kinds: `rewrite` (replace the version capture on the matched line with `to`, `{fixed}`
interpolated; `capture: numeric` swaps only the numeric prefix of a tag like `8.3.30-fpm`;
an optional `pattern` applies a regex to the whole line with `${1}` groups in `to`),
`insert-after` (a line after the match, tagged with the pack id and advisory), `tool` (a shell
command run in the file's directory, lockfiles only; `||` alternatives allowed), `manual`
(a checklist item). Lockfiles are never hand-edited.

Packs are tested by fixtures: `packs/<id>/testdata/` holds a tiny repo and `expected.json`;
`fumigator pack test` runs every pack against its fixture and diffs. A pack with no fixture
does not load.

## Why not YARA-X, Semgrep, Nuclei, gitleaks directly

Checked on 2026-10-22:

- **YARA-X** ([Go bindings](https://pkg.go.dev/github.com/VirusTotal/yara-x/go)) is the best
  byte-signature engine available, but the Go package wraps a Rust-built C library through cgo.
  That costs us the static cross-compile story and adds a Rust toolchain to every build. Our
  signature needs are strings and regexes over text files, which Go's `regexp` plus a keyword
  pre-filter handles. We borrow YARA's *shape* (strings + condition, size caps, per-rule
  metadata) in the `content` detector, not its engine. If a future incident needs real binary
  signatures (compiled artefacts, PE/ELF), add YARA-X as an optional detector behind a build
  tag; the pack format already has room for a `yara:` block.
- **Nuclei** ([file protocol](https://docs.projectdiscovery.io/templates/protocols/file)) is Go
  and embeddable, and its file templates look like our `content` detector. Its engine is built
  for HTTP targets; the file protocol is matchers over whole-file content with no version
  logic, no lockfile parsing, no fix. Its template format is a good reference for matcher
  and extractor syntax, and a pack could carry a `nuclei:` block later for live-host checks
  (the trust-chain probe against `*.we-have-a-problem.com` is a natural Nuclei template).
- **OSV-Scalibr** ([google/osv-scalibr](https://github.com/google/osv-scalibr)) is Go, Apache-2,
  and already parses every lockfile we care about (uv, poetry, Pipfile, npm/yarn/pnpm/bun,
  Cargo, composer, mix, Gemfile, go.mod, Maven/Gradle) plus Docker Compose and Kubernetes
  image references and GitHub Actions deps. Custom extractors and detectors are supported in
  library mode. **Use it** for the `package` detector instead of writing lockfile parsers.
- **Semgrep / ast-grep / opengrep** are AST engines for source code. Our exposure is in config
  and manifests, not code paths. The OCaml core is not embeddable from Go. Not needed now.
- **gitleaks** is Go with a TOML rule format (regex + keywords + entropy + allowlists). Its
  keyword pre-filter and allowlist design are worth copying into `content`; the library API is
  not stable enough to depend on.
- **GitHub code search API** (`search/code`): default branch only, files under 384 KB, 10
  requests/minute, 1,000 results per query. Useful as a *triage* query to find repos worth
  cloning (`org:X filename:Dockerfile php:8.1`), useless as the scan itself. The binary uses it
  to rank, then clones (shallow, concurrent) and scans locally.

## Host checks

`fumigator host` inventories the machine as tables, the way osquery does, and the pack's
`host:` block queries them. Each collector is one file under `internal/host/collectors/`
implementing `table.Collector` (name, columns, one-line doc, platforms, slow flag, Collect)
and registering itself in `init()`; `internal/host/table` holds the interface, the registry
and shared helpers. Collectors shell out to the manager that owns each runtime so the facts
match what that tool reports, and run concurrently; `--fast` skips the slow ones.
`fumigator host --collectors` prints the current list with columns and docs, which is the
source of truth rather than this document. As of 2026-10-22: system, tools, brew_packages,
node_installs, python_installs (pyenv, Homebrew, python.org, uv, Apple, conda base and envs,
project venvs, uv tool envs, pipx venvs), jdk_keystore_aliases, electron_apps, ca_bundles
(system, Homebrew, nix, certifi, gcloud, AWS CLI, conda envs, .app bundles),
binaries_embedding_roots (executables whose bytes contain a compromised root name: compiled-in
trust stores such as rustls + webpki-roots), container_vms (podman machine, Docker Desktop,
colima), php_ini.

A host check names a table, filters rows with `where` (literal or `re:`), and either compares
one column against a versions table (states vulnerable / eol / floating / unknown) or reports
every matching row as `present`. Fixes are commands with `{column}` and `{fixed}`
interpolated; `sudo: true` marks a command the tool prints but never runs; `suggest:` is a
command printed for the person next to the `manual:` reason, for decisions the tool must
not make; `once: true` collapses many rows into one action. The pack's `verify` probes run
after apply.

Why not osquery itself: it is a C++ daemon with its own build and privilege model, and the Go
bindings only write extensions for a running `osqueryd`. The dozen collectors we need are a
few hundred lines of Go and ship in the same static binary. The table shape is borrowed so
that, if fleet-wide coverage through Fleet or Kolide is wanted later, the same collectors can
be exposed as an osquery extension without changing the packs.

## CLI

```
fumigator scan   --pack php2shell-2026-10 [--pack ...] [--org ORG] ROOT...   -> findings/*.json, summary.md
fumigator gh     sync --org ORG DEST          enumerate org, shallow-clone missing, fetch stale
fumigator fix    --pack ID --findings DIR [--apply] [--run-tools] [--pr] [--only repo,...]
fumigator verify --pack ID [--image TAG] [--repo PATH]
fumigator host   --pack ID [--apply] [--only id,..] [--tables]   this machine
fumigator pack   test|lint [packs/ID]
```

Findings JSON is the contract between scan, fix, and the skills, and the audit trail:

```json
{"pack":"php2shell-2026-10","repo":"/abs/path","file":"Dockerfile","line":3,
 "detector":"php-image-tag","state":"vulnerable","current":"8.3.30","fixed":"8.3.36",
 "severity":"critical","fix":"rewrite","note":"..."}
```

## Migration order

1. Go core: walk + `regex-version` + `content` + findings + summary. Port both packs. Parity
   test against the Python scanner on the same roots.
2. `gh sync` (enumerate, clone, fetch) with a worker pool.
3. `fix` with `rewrite`/`insert-after`/`tool` and branch/commit/PR, ported from
   `remediate_repo.py`. **Done.** Findings carry `replace` (the exact substring to swap) or
   `fix_pattern` (a regex over the matched line) so the fixer needs no pack logic; it re-finds
   a line by content when numbers drift and skips an edit that is already present.
4. `package` detector on osv-scalibr; delete the hand-written lockfile parsing.
5. `host` subcommand, ported from `emudhra-remediate.sh`, driven by the pack's `host:` block.
   **Done**; the shell scripts are deleted.
6. Split the skill into two per-vulnerability skills plus `pack-authoring`; delete the Python.

Steps 1 to 3 are enough to run the org-wide scan and open the PRs with the binary.
