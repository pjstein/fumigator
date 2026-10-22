# Finding kinds: what each means, why it matters, where it lies

All version numbers come from `scripts/versions.json`. Severity is about exposure, not effort:
`critical` = exploitable now (PHP2Shell lines, vendored bundle that trusts the chain, WordPress core),
`high` = trusts the compromised chain until rebuilt, `medium` = probably fine after a rebuild but
not provable from the file, `low` = hygiene, `info` = nothing to do.

| kind | Found in | Why it matters | Fix mode | Known false positives |
|---|---|---|---|---|
| `image-tag` | `FROM` in Dockerfiles; `image:`/`container:` in compose, k8s, CI | Base images carry the runtime's CA bundle and, for `php:*`, the vulnerable interpreter. A tag below the fixed patch, or a floating tag (`node:22`, `golang:1.26`) that a cached layer can satisfy with an old build, means the image still trusts the chain after a rebuild. | auto (bump/pin) or manual (EOL line) | Private registry images with the same basename (`myorg/node:20`) are flagged by basename; check the note. `FROM $BASE` is reported `low`/manual: look at the `ARG` default. |
| `image-ca-upgrade` | `FROM alpine/debian/ubuntu/python` with no later `ca-certificates`/`certifi` step; `COPY --from=builder …ca-certificates.crt` | Distro bundles were fixed 2026-10-20/21; an image built from a cached base or with a copied bundle keeps the old roots. The inserted `RUN` line makes the rebuild self-correcting. | auto (Dockerfile) / manual (compose, builder stage) | A Dockerfile that installs ca-certificates in a differently-named step (`update-ca-trust`) is recognised; one that does it in an `ENTRYPOINT` script is not — demote to info in the PR. |
| `node-pin` | `.nvmrc`, `.node-version`, `.tool-versions`, `package.json` `engines.node` / `volta.node` | Node ignores the OS trust store; the fix is in 22.23.4 / 24.22.1 / 26.12.1 only. A pin to an EOL major (≤21, 23, 25) can never be fixed. | auto (same major) / manual (EOL) | `engines.node: ">=18"` is a floor, not a pin — the repo may already run on 22 in CI. The PR body says so; verify against CI config before upgrading. |
| `go-toolchain` | `go.mod` `go` and `toolchain` directives, `.tool-versions` | Go embeds its own SPKI denylist from 1.26.10 / 1.27.3. On macOS it also uses the OS store, so laptops are safe, but Linux containers and CI aren't. `GOTOOLCHAIN=auto` will download whatever the directive says. | auto | A `go 1.26` directive with no patch is a language version, not a toolchain pin; the scanner only flags three-part versions. |
| `python-dep` | `requirements*.txt`, `constraints*.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `runtime.txt` | `requests`, `httpx`, `urllib3`, `pip`, `boto3` all read `certifi`. A pin below 2026.10.19 is reinstalled on every deploy. | auto (text files: becomes a `>=` floor) / tool (lockfiles) | Transitive certifi with no direct pin isn't visible in `requirements.txt`; the lockfile scan catches it. |
| `cargo-dep` | `Cargo.lock` | `rustls` + `webpki-roots` embed Mozilla's roots; `native-tls` builds use the OS and aren't affected. | tool (`cargo update -p …`) | A crate that's in the lockfile but only built for a non-TLS feature. Rare. |
| `composer-dep` | `composer.lock` | `composer/ca-bundle` is used by Composer itself and by Guzzle-based apps. | tool | — |
| `mix-dep` | `mix.lock` | `castore` carries roots for Finch/Req/Mint; `erlang-certifi` has no fix yet (pending). | tool / manual | — |
| `electron-dep` | `package.json` | Electron apps ship Chromium's roots and don't get Chrome's CRLSet updates. | tool (`npm install -D electron@…`) | — |
| `ci-version` | `.github/workflows`, GitLab CI, Buildkite, CircleCI, Bitbucket | `setup-go`/`setup-node`/`setup-php` pins decide what builds the artifact; a job `container:` image is checked like a `FROM`. | auto / manual (EOL) | `go-version-file: go.mod` isn't flagged (go.mod is). Matrix lists (`[20, 22]`) are not parsed; look at them by hand when a workflow is touched. |
| `php-version` | `.tool-versions`, `composer.json` `require.php`, `composer.lock` `platform.php`, `.php-version` | PHP2Shell is unpatched on ≤ 8.1 except via vendor backports. A constraint like `^8.1` says the code *allows* 8.1; the actual server version is what matters. | auto (pin) / manual (constraint, EOL) | A library's `composer.json` with a wide constraint is normal; the risk is in the deployment, not the library. Downgrade to info for libraries. |
| `wordpress-version` | `wp-includes/version.php`, `wordpress:*` images | Three unauthenticated bugs in 2026 (wp2shell, CVE-2026-87902, and PHP2Shell underneath). Core below 7.1.2 / 7.0.6 / 6.9.5 should be assumed probed. | manual | A vendored copy of WordPress inside a theme repo for local dev — still worth updating, but not production. |
| `vendored-ca` | `*.pem`, `*.crt`, `cacert*`, `ca-bundle*` containing an affected root or intermediate name | A bundle that lists `AAA Certificate Services` or `emSign ECC Root CA - G3` trusts the compromised intermediates outright, with no revocation. Lambda layers, Terraform providers and old scrapers are the usual home. | manual (replace with [curl's bundle](https://curl.se/docs/caextract.html), or stop vendoring) | A bundle that contains the root *and* is only used for pinning a specific leaf (rare). Test fixtures that intentionally contain bad certs — check the path (`testdata/`). |
| `bun` | `oven/bun` images, `bun` in package.json, `bun-version` in CI | No fixed Bun release exists yet. | manual | — |
| `scan-error` | any | The parser threw; the file is probably unusual. Read it by hand. | — | — |

## What discovery deliberately skips

- Anything `.gitignore`d: `node_modules`, `.venv`, `target/`, build output. Those are installs, not
  source; the Mac remediation script handles the developer's machine, and the Dockerfile fix handles
  the image.
- Lockfiles for npm/yarn/pnpm: Node's roots are in the runtime, not a package.
- `Gemfile.lock`: Ruby uses the OpenSSL bundle.
- Terraform/Pulumi provider versions: too many providers to model; the `vendored-ca` content scan
  will catch a bundle checked into the repo, and the CI runner image is covered by `ci-version`.

## Adding a detector

Add a glob to `discover.sh`, a `scan_<thing>` method and a `DISPATCH` entry to `scan_repo.py`, and
if it's auto-fixable, a branch in `remediate_repo.py::fix`. Put the fixed version in
`versions.json`, never in code. Add a line to the fixture repo under `evals/` so the test covers it.
