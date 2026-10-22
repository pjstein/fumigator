# PR body shape

`fumigator fix --pr` generates this. If an agent writes or edits a PR body by hand, keep the
same four sections and the same register: a reviewer will see a dozen of these in a week and
should be able to read any one of them in a minute.

```markdown
## Why

Eight eMudhra intermediate CA certificates were compromised on 2026-10-17 (keys recoverable from
the certs; they chain to roots most toolchains trust and don't expire until 2040). Non-browser
clients only stop trusting them when their CA bundle or runtime is updated. Separately, PHP shipped
fixes for two unauthenticated RCEs (PHP2Shell, CVE-2026-109618/109619) on 2026-10-21 with
exploitation already in the wild. This PR brings `<repo>` onto fixed versions.

References: incident page · Go CVE-2026-111943 · PHP advisory

## Changes made

| File | Line | Before | After | Why |
|---|---|---|---|---|
| `Dockerfile` | 1 | `FROM golang:1.26.4-alpine` | `FROM golang:1.26.10-alpine` | Go 1.26.4 < 1.26.10 |

## Lockfiles regenerated

- `Cargo.lock`: `cargo update -p webpki-roots` (1.0.8 → 1.0.10)

## Still needs a human (not changed by this PR)

- [ ] **high** `.nvmrc`:1 — node-pin: 20.14.0 → 24.22.1. Node 20 is EOL, no fixed release; needs an upgrade decision

## Verify before merging

- [ ] `docker build --pull --no-cache` succeeds and the trust check prints nothing
- [ ] CI is green on this branch
- [ ] Any PHP service here runs `php -v` ≥ fixed after deploy
```

Rules the generator follows and a hand-written body should too:

- Every edited line appears in the table. Reviewers should never have to read the diff to know
  what changed and why.
- Manual items are checkboxes with severity, so a reviewer can tick them off or move them to an
  issue. They are the PR's real content when the automatic edits are small.
- No speculation about whether the repo was attacked. The scanner can't know; say what was
  exposed and what is now fixed.
- Branch name is always `sec/<pack-id>` and the title starts `fix(security):`, so the org can find
  them all with `gh search prs --owner ORG head:sec/<pack-id>`.
