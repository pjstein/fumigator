#!/usr/bin/env bash
# run_all.sh — drive both phases over every repo under one or more roots.
#
#   run_all.sh scan   [--out DIR] [--org ORG] ROOT...        Phase 1: discover + scan, write findings/ and summary.md
#   run_all.sh fix    [--out DIR] [--pr] [--run-tools] [--only REPO_NAME,...] [--skip REPO_NAME,...]
#                                                             Phase 2: remediate each repo with findings (dry run unless --apply)
#   run_all.sh fix --apply [--pr] ...                         actually edit, branch, and (with --pr) push + open PRs
#   run_all.sh clone  [--out DIR] --org ORG DEST_DIR           clone org repos that have no local checkout (from org-missing.txt)
#
# Outputs under DIR (default ./findings): repos.txt, candidates.txt, orphans.txt, <repo-name>.json, summary.md, fix-log.md
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-}"; shift || true
OUT=./findings; ORG=""; PR=0; APPLY=0; TOOLS=0; ONLY=""; SKIP=""; ROOTS=()
while [ $# -gt 0 ]; do case "$1" in
  --out) OUT="$2"; shift 2;; --org) ORG="$2"; shift 2;; --pr) PR=1; shift;; --apply) APPLY=1; shift;;
  --run-tools) TOOLS=1; shift;; --only) ONLY="$2"; shift 2;; --skip) SKIP="$2"; shift 2;;
  -h|--help) sed -n '2,11p' "$0"; exit 0;; *) ROOTS+=("$1"); shift;; esac; done
mkdir -p "$OUT"

case "$MODE" in
scan)
  [ ${#ROOTS[@]} -gt 0 ] || { echo "scan needs at least one ROOT"; exit 2; }
  "$HERE/discover.sh" --out "$OUT" ${ORG:+--org "$ORG"} "${ROOTS[@]}"
  : > "$OUT/summary.md"
  echo "# eMudhra / PHP2Shell repo scan — $(date '+%Y-%m-%d %H:%M')" >> "$OUT/summary.md"
  echo "" >> "$OUT/summary.md"; echo "| Repo | critical | high | medium | auto-fixable | tool | manual | top finding |" >> "$OUT/summary.md"; echo "|---|---|---|---|---|---|---|---|" >> "$OUT/summary.md"
  total=0
  for repo in $(cat "$OUT/repos.txt"); do
    name="$(basename "$repo")"
    files="$(awk -F'\t' -v r="$repo" '$1==r{print $2}' "$OUT/candidates.txt")"
    [ -n "$files" ] || continue
    # shellcheck disable=SC2086
    python3 -I "$HERE/scan_repo.py" "$repo" --json "$OUT/$name.json" --files $files > "$OUT/$name.txt" 2>&1 || true
    python3 -I - "$OUT/$name.json" "$repo" >> "$OUT/summary.md" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); F = [f for f in d["findings"] if f["severity"] != "info"]
if not F: sys.exit(0)
c = lambda k, v: sum(1 for f in F if f[k] == v)
top = F[0]; import os; print(f"| `{os.path.basename(sys.argv[2])}` | {c('severity','critical')} | {c('severity','high')} | {c('severity','medium')} | {c('fix','auto')} | {c('fix','tool')} | {c('fix','manual')} | `{top['file']}` {top['kind']} {top['current']} |")
PY
    n=$(python3 -I -c "import json,sys; print(sum(1 for f in json.load(open(sys.argv[1]))['findings'] if f['severity']!='info'))" "$OUT/$name.json")
    total=$((total+n)); [ "$n" -gt 0 ] && echo "$name: $n findings"
  done
  echo "" >> "$OUT/summary.md"
  if [ -s "$OUT/orphans.txt" ]; then
    echo "## Risk files outside any git repo ($(wc -l < "$OUT/orphans.txt"))" >> "$OUT/summary.md"; echo "" >> "$OUT/summary.md"
    echo "These are installs, vendored copies or backups; nothing to PR. Check each by hand or delete." >> "$OUT/summary.md"; echo "" >> "$OUT/summary.md"
    sed 's/^/- `/; s/$/`/' "$OUT/orphans.txt" >> "$OUT/summary.md"
  fi
  if [ -n "$ORG" ] && [ -s "$OUT/org-missing.txt" ]; then
    echo "" >> "$OUT/summary.md"; echo "## Org repos with no local checkout ($(wc -l < "$OUT/org-missing.txt"))" >> "$OUT/summary.md"
    echo "" >> "$OUT/summary.md"; echo "Run \`run_all.sh clone --org $ORG DEST\` then re-scan." >> "$OUT/summary.md"; echo "" >> "$OUT/summary.md"
    awk -F'\t' '{print "- " $1 "  <" $3 ">"}' "$OUT/org-missing.txt" >> "$OUT/summary.md"
  fi
  echo; echo "total findings: $total   summary: $OUT/summary.md"
  ;;
fix)
  : > "$OUT/fix-log.md"
  for j in "$OUT"/*.json; do
    [ -f "$j" ] || continue
    name="$(basename "$j" .json)"
    case ",$SKIP," in *",$name,"*) continue;; esac
    if [ -n "$ONLY" ]; then case ",$ONLY," in *",$name,"*) ;; *) continue;; esac; fi
    repo="$(python3 -I -c "import json,sys; print(json.load(open(sys.argv[1]))['repo'])" "$j")"
    [ -d "$repo" ] || { echo "$name: $repo missing"; continue; }
    echo "== $name ($repo)" | tee -a "$OUT/fix-log.md"
    python3 -I "$HERE/remediate_repo.py" "$repo" --findings "$j" $([ $APPLY = 1 ] && echo --apply) $([ $PR = 1 ] && echo --pr) $([ $TOOLS = 1 ] && echo --run-tools) 2>&1 | tee -a "$OUT/fix-log.md" || true
    echo | tee -a "$OUT/fix-log.md"
  done
  [ $APPLY = 1 ] || echo "(dry run — add --apply to edit on a branch, --pr to open PRs)"
  ;;
clone)
  [ -n "$ORG" ] && [ ${#ROOTS[@]} -eq 1 ] || { echo "clone needs --org ORG and one DEST_DIR"; exit 2; }
  [ -s "$OUT/org-missing.txt" ] || { echo "no $OUT/org-missing.txt; run scan --org first"; exit 2; }
  mkdir -p "${ROOTS[0]}"
  while IFS=$'\t' read -r name ssh url; do
    [ -d "${ROOTS[0]}/$name" ] && continue
    echo "cloning $name"; git clone -q --depth 50 "$ssh" "${ROOTS[0]}/$name" || echo "  failed: $name"
  done < "$OUT/org-missing.txt"
  echo "re-run: run_all.sh scan --out $OUT ${ROOTS[0]}"
  ;;
*) sed -n '2,11p' "$0"; exit 2;;
esac
