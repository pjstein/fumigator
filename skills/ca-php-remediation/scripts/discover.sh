#!/usr/bin/env bash
# discover.sh — Phase 1. Find every git repo and every risk-bearing file under one or more roots, fast, with rg.
#
#   discover.sh [--out DIR] [--org GITHUB_ORG] ROOT [ROOT...]
#
# Writes to DIR (default ./findings):
#   repos.txt          one absolute repo path per line (dirs containing .git)
#   candidates.txt     repo<TAB>relative file path, for every file the scanner should parse
#   orphans.txt        candidate files not inside any git repo (installs, vendored copies, backups)
#   org-missing.txt    (with --org) repos in the GitHub org that have no local checkout
#
# rg honours .gitignore, so node_modules, venvs and build output are skipped unless committed.
# Nothing here modifies anything.
set -euo pipefail
OUT=./findings; ORG=""
while [ $# -gt 0 ]; do case "$1" in
  --out) OUT="$2"; shift 2;; --org) ORG="$2"; shift 2;; -h|--help) sed -n '2,14p' "$0"; exit 0;; *) break;; esac; done
[ $# -gt 0 ] || { echo "usage: discover.sh [--out DIR] [--org ORG] ROOT..."; exit 2; }
command -v rg >/dev/null || { echo "ripgrep (rg) is required"; exit 1; }
mkdir -p "$OUT"; : > "$OUT/repos.txt"; : > "$OUT/candidates.txt"; : > "$OUT/orphans.txt"

# --- 1. git repos (walk .git dirs; depth-limited so a huge disk stays quick) ---
for root in "$@"; do
  find "$root" -maxdepth 6 -type d -name .git -not -path '*/node_modules/*' -not -path '*/.cache/*' -prune 2>/dev/null \
    | sed 's#/\.git$##'
done | sort -u > "$OUT/repos.txt"
echo "repos: $(wc -l < "$OUT/repos.txt")"

# --- 2. candidate files by name (one rg pass per root) ---
NAME_GLOBS=(
  -g 'Dockerfile' -g 'Dockerfile.*' -g '*.dockerfile' -g 'Containerfile'
  -g 'docker-compose*.y*ml' -g 'compose*.y*ml'
  -g '.nvmrc' -g '.node-version' -g '.tool-versions' -g '.python-version' -g 'runtime.txt'
  -g 'package.json' -g 'go.mod' -g 'Cargo.lock' -g 'composer.json' -g 'composer.lock' -g 'mix.lock'
  -g 'requirements*.txt' -g 'pyproject.toml' -g 'poetry.lock' -g 'uv.lock' -g 'Pipfile.lock' -g 'constraints*.txt'
  -g '**/.github/workflows/*.y*ml' -g '.gitlab-ci.yml' -g 'bitbucket-pipelines.yml' -g '**/.buildkite/*.y*ml' -g '**/.circleci/config.yml'
  -g 'fly.toml' -g 'app.yaml' -g 'serverless.y*ml' -g 'template.y*ml' -g 'Procfile'
  -g '**/wp-includes/version.php' -g '.php-version' -g 'php.ini' -g '*.ini'
  -g '**/k8s/**/*.y*ml' -g '**/kube/**/*.y*ml' -g '**/manifests/**/*.y*ml' -g '**/charts/**/values*.y*ml' -g '**/deploy/**/*.y*ml'
)
for root in "$@"; do
  rg --files --hidden --no-messages -g '!.git' -g '!node_modules' -g '!**/site-packages/**' "${NAME_GLOBS[@]}" "$root" 2>/dev/null || true
done | sort -u > "$OUT/_by_name.txt"

# --- 3. candidate files by content: vendored CA bundles that still carry the affected roots ---
for root in "$@"; do
  rg -l --hidden --no-messages -g '!.git' -g '!node_modules' -g '*.pem' -g '*.crt' -g '*.cer' -g '*.bundle' -g 'cacert*' -g 'ca-bundle*' -g 'ca-certificates*' \
     -e 'AAA Certificate Services' -e 'emSign ECC Root CA - G3' -e 'emSign Root TLS CA - G3' -e 'EM (DV|OV|EV) TLS CA - G3[BC]' "$root" 2>/dev/null || true
done | sort -u > "$OUT/_by_content.txt"

# --- 4. assign each candidate to its repo (longest matching repo prefix) ---
python3 -I - "$OUT" <<'PY'
import sys, os
out = sys.argv[1]
repos = sorted((l.rstrip("\n") for l in open(f"{out}/repos.txt") if l.strip()), key=len, reverse=True)
files = set()
for name in ("_by_name.txt", "_by_content.txt"):
    files.update(l.rstrip("\n") for l in open(f"{out}/{name}") if l.strip())
cand, orph = [], []
for f in sorted(files):
    for r in repos:
        if f == r or f.startswith(r + os.sep):
            cand.append(f"{r}\t{os.path.relpath(f, r)}"); break
    else:
        orph.append(f)
open(f"{out}/candidates.txt", "w").write("\n".join(cand) + ("\n" if cand else ""))
open(f"{out}/orphans.txt", "w").write("\n".join(orph) + ("\n" if orph else ""))
print(f"candidate files in repos: {len(cand)}   outside any repo: {len(orph)}")
PY
rm -f "$OUT/_by_name.txt" "$OUT/_by_content.txt"

# --- 5. optional: compare against the GitHub org ---
if [ -n "$ORG" ]; then
  command -v gh >/dev/null || { echo "gh not found; skipping --org"; exit 0; }
  gh repo list "$ORG" --limit 1000 --no-archived --json name,sshUrl,url -q '.[] | "\(.name)\t\(.sshUrl)\t\(.url)"' > "$OUT/org-repos.tsv"
  : > "$OUT/org-missing.txt"
  while IFS=$'\t' read -r name ssh url; do
    if ! grep -q "/$name\$" "$OUT/repos.txt"; then echo -e "$name\t$ssh\t$url" >> "$OUT/org-missing.txt"; fi
  done < "$OUT/org-repos.tsv"
  echo "org repos: $(wc -l < "$OUT/org-repos.tsv")   not checked out locally: $(wc -l < "$OUT/org-missing.txt")  (see $OUT/org-missing.txt)"
fi
echo "wrote $OUT/{repos.txt,candidates.txt,orphans.txt}"
