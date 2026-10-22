#!/usr/bin/env python3
"""remediate_repo.py — Phase 2. Apply fixes for a repo's findings, on a branch, and optionally open a PR.

  remediate_repo.py REPO_DIR --findings findings.json [--apply] [--pr] [--branch NAME] [--base main]
                    [--run-tools] [--dry-run]

Default is a dry run that prints every edit it would make. --apply edits files in place on a new branch
(created from the current HEAD; refuses if the working tree is dirty). --run-tools additionally runs
lockfile tools (cargo update, uv lock, composer update, mix deps.update, npm install) when they are on
PATH. --pr commits, pushes and opens a GitHub PR with `gh`, with a body listing what changed and what
still needs a human. Findings marked fix=manual are never edited; they go in the PR body as a checklist.

Exit 0 = ran (dry run printed, or edits applied/PR opened); 2 = refused or failed (dirty tree, push/PR error).
"""
import argparse, json, os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ADVISORY = "https://emudhra.we-have-a-problem.com/#developers"
PHP_ADVISORY = "https://www.php.net/archive/2026.php#2026-10-21-5"

def sh(cmd, cwd, check=True):
    r = subprocess.run(cmd, cwd=cwd, shell=isinstance(cmd, str), text=True, capture_output=True)
    if check and r.returncode: raise RuntimeError(f"{cmd}\n{r.stdout}{r.stderr}")
    return r

class Remediator:
    def __init__(self, repo, findings, apply, run_tools, V):
        self.repo, self.findings, self.apply, self.run_tools, self.V = repo, findings, apply, run_tools, V
        self.edits, self.tool_runs, self.manual, self.skipped = [], [], [], []
        self._cache = {}

    def read(self, rel):
        if rel not in self._cache: self._cache[rel] = open(os.path.join(self.repo, rel), errors="replace").read().splitlines(keepends=True)
        return self._cache[rel]

    def set_line(self, rel, ln, new, why):
        lines = self.read(rel); old = lines[ln - 1]
        if old.rstrip("\n") == new.rstrip("\n"): return
        self.edits.append((rel, ln, old.rstrip("\n"), new.rstrip("\n"), why)); lines[ln - 1] = new if new.endswith("\n") else new + "\n"

    def insert_after(self, rel, ln, text, why):
        lines = self.read(rel); lines.insert(ln, text if text.endswith("\n") else text + "\n")
        self.edits.append((rel, ln + 1, "", text.rstrip("\n"), why))
        # shift later findings on this file
        for f in self.findings:
            if f["file"] == rel and f["line"] > ln: f["line"] += 1

    def flush(self):
        for rel, lines in self._cache.items():
            if any(e[0] == rel for e in self.edits): open(os.path.join(self.repo, rel), "w").write("".join(lines))

    # ---- per-kind fixers ----
    def fix(self, f):
        k, rel, ln = f["kind"], f["file"], f["line"]
        if f["fix"] == "manual": self.manual.append(f); return
        if f["fix"] == "none": return
        if f["fix"] == "tool":
            self.tool_runs.append(f); return
        if k == "image-tag" and ln:
            line = self.read(rel)[ln - 1]
            self.set_line(rel, ln, line.replace(f["current"], f["fixed"], 1), f["note"])
        elif k == "image-ca-upgrade" and ln:
            if f["fixed"].startswith("RUN upgrade"):
                img = f.get("base_image", f["current"]); base = img.split("/")[-1].split(":")[0]; tag = img.split(":")[-1] if ":" in img else ""
                apk = "RUN apk upgrade --no-cache ca-certificates"
                apt = "RUN apt-get update && apt-get install -y --only-upgrade ca-certificates && rm -rf /var/lib/apt/lists/*"
                if base == "alpine" or "alpine" in tag: run = apk
                elif base in ("debian", "ubuntu") or any(t in tag for t in ("bookworm", "bullseye", "trixie", "slim", "jammy", "noble")): run = apt
                else: run = "RUN (apk upgrade --no-cache ca-certificates 2>/dev/null || (apt-get update && apt-get install -y --only-upgrade ca-certificates && rm -rf /var/lib/apt/lists/*))"
                ln = f.get("insert_after", ln)
            else: run = "RUN pip install --no-cache-dir -U certifi pip"
            if rel.endswith((".yml", ".yaml")): self.manual.append(dict(f, note=f["note"] + " (compose/k8s image: fix in that image's Dockerfile)")); return
            self.insert_after(rel, ln, run + "  # eMudhra CA compromise, Oct 2026: " + ADVISORY, f["note"])
        elif k in ("node-pin", "ci-version", "go-toolchain", "php-version") and ln:
            line = self.read(rel)[ln - 1]
            new = re.sub(r"v?" + re.escape(f["current"]) + r"(?![\d.])", f["fixed"], line, count=1)
            if new == line and f["current"] == "unpinned": return
            self.set_line(rel, ln, new, f["note"])
        elif k == "node-pin" and not ln and rel.endswith("package.json"):
            d = json.load(open(os.path.join(self.repo, rel))); changed = False
            if "engines" in d and "node" in d["engines"]:
                d["engines"]["node"] = f">={f['fixed']}"; changed = True
            if "volta" in d and "node" in d["volta"]: d["volta"]["node"] = f["fixed"]; changed = True
            if changed:
                self.edits.append((rel, 0, f["current"], f["fixed"], f["note"]))
                self._cache[rel] = [json.dumps(d, indent=2) + "\n"]
        elif k == "python-dep" and ln:
            line = self.read(rel)[ln - 1]
            if f["current"] == "unpinned": self.set_line(rel, ln, re.sub(r"certifi\s*$", f"certifi>={f['fixed']}", line), f["note"])
            else: self.set_line(rel, ln, line.replace(f["current"], f["fixed"], 1).replace("certifi==", "certifi>=", 1), f["note"])
        else: self.skipped.append(f)

    def run_tool_fixes(self):
        done = []
        for f in self.tool_runs:
            cmd = f["note"] if f["note"].split()[0] in ("cargo", "uv", "poetry", "pipenv", "composer", "mix", "npm") else None
            if not cmd: self.manual.append(f); continue
            tool = cmd.split()[0]
            if not self.run_tools or not shutil.which(tool):
                self.manual.append(dict(f, note=f"run: {cmd}")); continue
            cwd = os.path.join(self.repo, os.path.dirname(f["file"]))
            r = sh(cmd, cwd, check=False)
            if r.returncode: self.manual.append(dict(f, note=f"`{cmd}` failed: {(r.stderr or r.stdout)[-300:]}"))
            else: done.append((f, cmd))
        self.tool_runs = done

    def run(self):
        for f in self.findings: self.fix(f)
        if self.apply:
            self.flush(); self.run_tool_fixes()
        else:
            for f in self.tool_runs: pass
        return self

# ---------- git / PR ----------
def pr_body(rem, repo_name):
    V = rem.V; L = []
    L.append("## Why\n")
    L.append(f"Eight eMudhra intermediate CA certificates were compromised on 2026-10-17 (keys recoverable from the certs; they chain to roots most toolchains trust and don't expire until 2040). Non-browser clients only stop trusting them when their CA bundle or runtime is updated. Separately, PHP shipped fixes for two unauthenticated RCEs (PHP2Shell, CVE-2026-109618/109619) on 2026-10-21 with exploitation already in the wild. This PR brings `{repo_name}` onto fixed versions.\n")
    L.append(f"References: [incident page]({ADVISORY}) · [Go CVE-2026-111943](https://groups.google.com/g/golang-announce/c/66pojueaQek) · [PHP advisory]({PHP_ADVISORY})\n")
    if rem.edits:
        L.append("## Changes made\n"); L.append("| File | Line | Before | After | Why |\n|---|---|---|---|---|")
        for rel, ln, old, new, why in rem.edits: L.append(f"| `{rel}` | {ln or ''} | `{old[:60]}` | `{new[:60]}` | {why} |")
        L.append("")
    if rem.tool_runs:
        L.append("## Lockfiles regenerated\n")
        for f, cmd in rem.tool_runs: L.append(f"- `{f['file']}`: `{cmd}` ({f['current']} → {f['fixed']})")
        L.append("")
    if rem.manual:
        L.append("## Still needs a human (not changed by this PR)\n")
        for f in rem.manual: L.append(f"- [ ] **{f['severity']}** `{f['file']}`{(':' + str(f['line'])) if f['line'] else ''} — {f['kind']}: {f['current']} → {f['fixed']}. {f['note']}")
        L.append("")
    L.append("## Verify before merging\n")
    L.append("- [ ] `docker build --pull --no-cache` succeeds and `docker run --rm <image> sh -c 'curl -sSf https://dv-g3b-emudhra.we-have-a-problem.com/ && echo STILL_TRUSTS'` prints nothing (a cert error is the good outcome)")
    L.append("- [ ] CI is green on this branch")
    L.append("- [ ] Any PHP service here runs `php -v` ≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 after deploy")
    L.append("\n🤖 Generated with [Claude Code](https://claude.com/claude-code)\n")
    return "\n".join(L)

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo"); ap.add_argument("--findings", required=True); ap.add_argument("--apply", action="store_true")
    ap.add_argument("--pr", action="store_true"); ap.add_argument("--run-tools", action="store_true")
    ap.add_argument("--branch", default="sec/emudhra-php2shell-2026-10"); ap.add_argument("--base", default=None)
    ap.add_argument("--versions", default=os.path.join(HERE, "versions.json")); ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--body-only", metavar="PATH", help="write the PR body for these findings to PATH and exit (no git)")
    a = ap.parse_args(); repo = os.path.abspath(a.repo); apply = a.apply and not a.dry_run
    data = json.load(open(a.findings)); findings = data["findings"] if isinstance(data, dict) else data
    findings = [f for f in findings if f["kind"] != "scan-error"]
    V = json.load(open(a.versions))
    if a.body_only:
        rem = Remediator(repo, findings, False, False, V).run()
        open(a.body_only, "w").write(pr_body(rem, os.path.basename(repo))); print(f"wrote {a.body_only}"); return 0
    is_git = os.path.isdir(os.path.join(repo, ".git"))
    if apply and is_git:
        if sh("git status --porcelain", repo).stdout.strip(): print("refusing: working tree is dirty", file=sys.stderr); return 2
        base = a.base or sh("git rev-parse --abbrev-ref HEAD", repo).stdout.strip()
        if sh(f"git rev-parse --verify --quiet {a.branch}", repo, check=False).returncode == 0: sh(f"git checkout {a.branch}", repo)
        else: sh(f"git checkout -b {a.branch}", repo)
    elif apply and not is_git: print("not a git repo: editing in place, no branch/PR", file=sys.stderr)

    rem = Remediator(repo, findings, apply, a.run_tools, V).run()
    tag = "APPLIED" if apply else "WOULD"
    for rel, ln, old, new, why in rem.edits: print(f"  {tag} edit  {rel}:{ln}\n    - {old}\n    + {new}")
    for f in (rem.tool_runs if not apply else []): print(f"  WOULD run   {f['note']}  (in {os.path.dirname(f['file']) or '.'})")
    for f, cmd in (rem.tool_runs if apply else []): print(f"  RAN         {cmd}  ({f['file']})")
    for f in rem.manual: print(f"  MANUAL      [{f['severity']}] {f['file']}:{f['line']} {f['kind']} {f['current']} -> {f['fixed']}  {f['note']}")
    for f in rem.skipped: print(f"  SKIPPED     {f['file']}:{f['line']} {f['kind']} (no fixer)")
    nothing = not (rem.edits or rem.tool_runs or rem.manual)
    if nothing: print("nothing to do"); return 0

    if apply and is_git and a.pr:
        if not sh("git status --porcelain", repo).stdout.strip() and not rem.manual: print("no file changes; not opening a PR"); return 0
        name = os.path.basename(repo)
        # stage only what the remediation touched: tracked files, plus lockfiles a tool may have created.
        # never `git add -A`: a tool run can leave node_modules/ or vendor/ in a repo with no .gitignore.
        sh("git add -u", repo)
        for rel, _, _, _, _ in rem.edits: sh(["git", "add", "--", rel], repo, check=False)
        for root, dirs, files in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor", "target", ".venv")]
            for f in files:
                if f in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "uv.lock", "poetry.lock", "composer.lock", "mix.lock", "Pipfile.lock"): sh(["git", "add", "--", os.path.relpath(os.path.join(root, f), repo)], repo, check=False)
        untracked = sh("git ls-files --others --exclude-standard", repo).stdout.split()
        if untracked: print(f"  note: {len(untracked)} untracked file(s) left out of the commit (e.g. {untracked[0]}); add a .gitignore if a tool created them")
        if sh("git diff --cached --quiet", repo, check=False).returncode != 0:
            msg = "sec: update CA bundles/runtimes for eMudhra CA compromise and PHP2Shell\n\n" + \
                  "\n".join(f"- {rel}:{ln}: {old[:50]} -> {new[:50]}" for rel, ln, old, new, _ in rem.edits) + \
                  "\n\nCo-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>\n"
            sh(["git", "commit", "-q", "-m", msg], repo)
        body = pr_body(rem, name); open(os.path.join(repo, ".git", "PR_BODY.md"), "w").write(body)
        if sh("git remote get-url origin", repo, check=False).returncode: print("no 'origin' remote; branch committed locally, PR body at .git/PR_BODY.md"); return 0
        if not shutil.which("gh") or sh("gh auth status", repo, check=False).returncode: print("gh missing or not authenticated; branch committed, PR body at .git/PR_BODY.md — push and open the PR by hand"); return 0
        r = sh(f"git push -u origin {a.branch}", repo, check=False)
        if r.returncode: print(f"push failed: {r.stderr.strip()[-300:]}"); return 2
        r = sh(["gh", "pr", "create", "--title", f"sec: eMudhra CA compromise + PHP2Shell remediation ({name})", "--body-file", os.path.join(repo, ".git", "PR_BODY.md"), "--base", base, "--head", a.branch], repo, check=False)
        print(r.stdout.strip() or r.stderr.strip())
        if r.returncode and "already exists" in r.stderr: print("PR already exists for this branch; pushed update")
        elif r.returncode: return 2
    elif apply and is_git:
        print(f"changes applied on branch {a.branch}; review with git diff, then re-run with --pr")
    return 0

if __name__ == "__main__":
    sys.exit(main())
