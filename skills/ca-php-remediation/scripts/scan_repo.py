#!/usr/bin/env python3
"""scan_repo.py — Phase 1 detector. Turns candidate files into concrete findings. Read-only.

  scan_repo.py REPO_DIR [--files REL ...] [--versions versions.json] [--json OUT]

With --files, only those paths (relative to REPO_DIR) are parsed — pass what discover.sh found.
Without it, the repo is walked (slower; honours no .gitignore). Prints a human summary to stdout
and, with --json, writes findings as a JSON list. Each finding:

  {"file","line","kind","current","fixed","severity","fix": "auto"|"tool"|"manual","note"}

kinds: image-tag, image-ca-upgrade, node-pin, go-toolchain, python-dep, cargo-dep, composer-dep,
       mix-dep, electron-dep, vendored-ca, php-version, wordpress-version, ci-version, bun
"""
import argparse, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))

def vtuple(v):
    v = re.sub(r"^[vV^~>=<\s]*", "", str(v)); v = re.split(r"[^0-9.]", v, maxsplit=1)[0]
    return tuple(int(x) for x in v.split(".") if x != "")

def vlt(a, b):
    try: return vtuple(a) < vtuple(b)
    except Exception: return False

def major_minor(v, parts):
    t = vtuple(v); return ".".join(str(x) for x in t[:parts]) if t else ""

class Scanner:
    def __init__(self, repo, V):
        self.repo, self.V, self.out = repo, V, []

    def add(self, file, line, kind, current, fixed, severity, fix, note=""):
        self.out.append(dict(file=file, line=line, kind=kind, current=str(current), fixed=str(fixed),
                             severity=severity, fix=fix, note=note))

    # ---------- container images (Dockerfile FROM, compose/k8s image:) ----------
    IMG_RE = re.compile(r"""^\s*(?:FROM\s+(?:--platform=\S+\s+)?|image:\s*["']?)([\w./-]+(?::[\w.@+-]+)?)""", re.I)

    def check_image(self, file, ln, image):
        name, _, tag = image.partition(":")
        base = name.split("/")[-1]; tag = tag or "latest"
        V = self.V
        def eol(what, cur): self.add(file, ln, "image-tag", f"{name}:{tag}", "—", "high", "manual", f"{what} {cur} is end-of-life; no fixed release exists. Move to a supported line.")
        def bump(what, cur, fixed): self.add(file, ln, "image-tag", f"{name}:{tag}", f"{name}:{tag.replace(cur, fixed, 1)}", "high", "auto", f"{what} {cur} < {fixed}")
        if base in ("golang", "go"):
            mm = major_minor(tag, 2)
            if mm and mm in V["go"]:
                if vtuple(tag) < vtuple(V["go"][mm]) and len(vtuple(tag)) >= 3: bump("Go", major_minor(tag, 3), V["go"][mm])
                elif len(vtuple(tag)) == 2: self.add(file, ln, "image-tag", image, f"{name}:{V['go'][mm]}{tag[len(mm):]}", "high", "auto", f"floating {mm} tag; pin to {V['go'][mm]} so a cached layer can't hide an old toolchain")
            elif mm and vlt(mm, V["go_eol_below"]): eol("Go", mm)
            elif tag in ("latest", "alpine", "bookworm"): self.add(file, ln, "image-tag", image, f"{name}:{V['go']['1.27']}", "medium", "auto", "floating tag; pin")
        elif base == "node":
            maj = major_minor(tag, 1)
            if maj in V["node_eol"]: eol("Node", maj)
            elif maj in V["node"]:
                if len(vtuple(tag)) >= 3 and vlt(tag, V["node"][maj]): bump("Node", major_minor(tag, 3), V["node"][maj])
                elif len(vtuple(tag)) < 3: self.add(file, ln, "image-tag", image, f"{name}:{V['node'][maj]}{tag[len(major_minor(tag, len(vtuple(tag)))):]}", "high", "auto", f"floating {tag}; pin to {V['node'][maj]}")
            elif tag in ("latest", "lts", "current", "alpine", "slim"): self.add(file, ln, "image-tag", image, f"{name}:{V['node']['24']}", "medium", "auto", "floating tag; pin")
        elif base == "php" or base == "wordpress":
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", tag)
            if base == "wordpress": self.add(file, ln, "wordpress-version", image, "rebuilt ≥ 2026-10-21 with PHP ≥ fixed", "critical", "manual", "WordPress image: must run PHP ≥ 8.2.35/8.3.36/8.4.27/8.5.12 (PHP2Shell) and WP ≥ 7.1.2 / 6.9.5 / 7.0.6. Re-pull and check the digest date.")
            if m:
                mm = major_minor(m.group(1), 2)
                if mm in V["php_eol"] or m.group(1).split(".")[0] in V["php_eol"]: eol("PHP", mm); self.out[-1]["severity"] = "critical"; self.out[-1]["note"] += " PHP2Shell (CVE-2026-109618/109619) is unpatched on this line."
                elif mm in V["php"]:
                    if len(vtuple(m.group(1))) >= 3 and vlt(m.group(1), V["php"][mm]): bump("PHP", m.group(1), V["php"][mm]); self.out[-1]["severity"] = "critical"
                    elif len(vtuple(m.group(1))) == 2: self.add(file, ln, "image-tag", image, image.replace(mm, V["php"][mm], 1), "critical", "auto", f"floating {mm}; pin to {V['php'][mm]} (PHP2Shell)")
            elif base == "php": self.add(file, ln, "image-tag", image, f"{name}:{V['php']['8.4']}", "critical", "manual", "floating php tag; pin to a fixed release (PHP2Shell)")
        elif base in ("python", "pypy"):
            self.add(file, ln, "image-ca-upgrade", image, "RUN pip install -U certifi pip", "medium", "auto", "python images ship stale certifi; upgrade it in the build (and in the app's lockfile)")
        elif base in ("alpine", "debian", "ubuntu"):
            self.add(file, ln, "image-ca-upgrade", image, "RUN upgrade ca-certificates", "high", "auto", f"base image may predate the fixed ca-certificates ({V['images'].get(base,'')}); add an explicit upgrade after FROM")
        elif base == "bun" or name.startswith("oven/bun"):
            self.add(file, ln, "bun", image, "—", "high", "manual", "Bun has no fixed release; mount a clean bundle via NODE_EXTRA_CA_CERTS or build with node")
        elif base in ("composer",):
            self.add(file, ln, "image-tag", image, "composer:2 (pull after 2026-10-21)", "medium", "manual", "composer image bundles PHP; re-pull and verify PHP version")

    def scan_dockerfile(self, rel):
        path = os.path.join(self.repo, rel); lines = open(path, errors="replace").read().splitlines()
        # split into stages so an upgrade step in one stage doesn't vouch for another
        stages = []  # (start_line_idx, end_idx_exclusive, image, name)
        for i, l in enumerate(lines):
            m = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", l, re.I)
            if m:
                if stages: stages[-1][1] = i
                stages.append([i, len(lines), m.group(1), (m.group(2) or "").lower()])
        def has_ca(st): return any(re.match(r"^\s*RUN\b", l) and re.search(r"ca-certificates|update-ca-trust|update-ca-certificates", l) for l in lines[st[0]:st[1]])
        def has_certifi(st): return any(re.match(r"^\s*RUN\b", l) and re.search(r"pip3?\s+install.*certifi", l) for l in lines[st[0]:st[1]])
        def stage_named(n):
            n = n.lower()
            for k, st in enumerate(stages):
                if st[3] == n or str(k) == n: return st
            return None
        for st in stages:
            start, end, img, _ = st
            if img.lower().startswith("scratch"): continue
            if "$" in img: self.add(rel, start + 1, "image-tag", img, "—", "low", "manual", "parameterised base image; check the ARG default"); continue
            before = len(self.out); self.check_image(rel, start + 1, img)
            # a stage that copies its bundle from a builder stage is covered if that builder upgrades it
            copied_ok = False
            for l in lines[start:end]:
                m = re.search(r"COPY\s+--from=(\S+)\s+\S*ca-certificates\.crt", l)
                if m:
                    src = stage_named(m.group(1))
                    if src and has_ca(src): copied_ok = True
                    elif src and "$" not in src[2]:
                        self.add(rel, start + 1 + lines[start:end].index(l), "image-ca-upgrade", l.strip(), "RUN upgrade ca-certificates", "high", "auto", f"CA bundle copied from stage '{m.group(1)}' ({src[2]}), which has no ca-certificates upgrade step; one is inserted after that stage's FROM")
                        self.out[-1]["insert_after"] = src[0] + 1; self.out[-1]["base_image"] = src[2]
                    else: self.add(rel, start + 1 + lines[start:end].index(l), "image-ca-upgrade", l.strip(), "upgrade ca-certificates in the builder stage", "high", "manual", f"CA bundle copied from stage '{m.group(1)}'; add an upgrade step there")
            for f in self.out[before:]:
                if f["kind"] == "image-ca-upgrade" and ((f["fixed"].startswith("RUN upgrade") and (has_ca(st) or copied_ok)) or (f["fixed"].startswith("RUN pip") and has_certifi(st))):
                    f["severity"], f["fix"], f["note"] = "info", "none", "this stage already upgrades its bundle; rebuild with --pull --no-cache"

    def scan_compose_or_k8s(self, rel):
        for i, l in enumerate(open(os.path.join(self.repo, rel), errors="replace")):
            m = re.match(r"""^\s*(?:-\s*)?(?:image|container):\s*["']?([\w./-]+(?::[\w.@+-]+)?)""", l)
            if m and "$" not in m.group(1):
                before = len(self.out); self.check_image(rel, i + 1, m.group(1))
                for f in self.out[before:]:
                    if f["kind"] == "image-ca-upgrade": f["fix"] = "manual"; f["note"] += " (fix in that image's Dockerfile, then re-pull here)"

    # ---------- version pins ----------
    def node_pin(self, rel, ln, v, ctx):
        V = self.V; maj = major_minor(v, 1)
        if not maj: return
        if maj in V["node_eol"]: self.add(rel, ln, "node-pin", v, V["node"]["24"], "high", "manual", f"{ctx}: Node {maj} is EOL, no fixed release; needs an upgrade decision")
        elif maj in V["node"] and (len(vtuple(v)) < 3 or vlt(v, V["node"][maj])):
            self.add(rel, ln, "node-pin", v, V["node"][maj], "high", "auto", f"{ctx}: pin below fixed {V['node'][maj]}")

    def scan_nvmrc(self, rel):
        for i, l in enumerate(open(os.path.join(self.repo, rel), errors="replace")):
            s = l.strip().lstrip("v")
            if s and not s.startswith("lts"): self.node_pin(rel, i + 1, s, os.path.basename(rel))
            elif s.startswith("lts"): self.add(rel, i + 1, "node-pin", s, self.V["node"]["24"], "low", "auto", "lts/* alias resolves to whatever nvm has cached; pin explicitly")

    def scan_tool_versions(self, rel):
        for i, l in enumerate(open(os.path.join(self.repo, rel), errors="replace")):
            p = l.split()
            if len(p) < 2: continue
            if p[0] in ("nodejs", "node"): self.node_pin(rel, i + 1, p[1], ".tool-versions")
            if p[0] in ("golang", "go"):
                mm = major_minor(p[1], 2)
                if mm in self.V["go"] and vlt(p[1], self.V["go"][mm]): self.add(rel, i + 1, "go-toolchain", p[1], self.V["go"][mm], "high", "auto", ".tool-versions go pin")
            if p[0] == "php":
                mm = major_minor(p[1], 2)
                if mm in self.V["php"] and vlt(p[1], self.V["php"][mm]): self.add(rel, i + 1, "php-version", p[1], self.V["php"][mm], "critical", "auto", ".tool-versions php pin (PHP2Shell)")
                elif mm in self.V["php_eol"]: self.add(rel, i + 1, "php-version", p[1], "8.3.36", "critical", "manual", "EOL PHP line pinned; PHP2Shell unpatched")

    def scan_package_json(self, rel):
        try: d = json.load(open(os.path.join(self.repo, rel)))
        except Exception: return
        ev = (d.get("engines") or {}).get("node")
        if ev:
            m = re.search(r"(\d+(?:\.\d+){0,2})", ev)
            if m: self.node_pin(rel, 0, m.group(1), f"engines.node '{ev}'")
        vv = (d.get("volta") or {}).get("node")
        if vv: self.node_pin(rel, 0, vv, "volta.node")
        for sec in ("devDependencies", "dependencies"):
            ev = (d.get(sec) or {}).get("electron")
            if ev:
                m = re.search(r"(\d+)\.(\d+)\.(\d+)", ev); maj = m.group(1) if m else None
                if maj and maj in self.V["electron"] and vlt(m.group(0), self.V["electron"][maj]): self.add(rel, 0, "electron-dep", ev, self.V["electron"][maj], "high", "tool", f"npm install -D electron@{self.V['electron'][maj]}")
                elif maj and int(maj) < 42: self.add(rel, 0, "electron-dep", ev, self.V["electron"]["44"], "high", "manual", "Electron line below 42 has no fix; major upgrade needed")
        for sec in ("devDependencies", "dependencies"):
            if "bun" in (d.get(sec) or {}) or "bun-types" in (d.get(sec) or {}): self.add(rel, 0, "bun", "bun", "—", "medium", "manual", "project uses Bun; no fixed release yet")

    def scan_go_mod(self, rel):
        V = self.V
        for i, l in enumerate(open(os.path.join(self.repo, rel), errors="replace")):
            m = re.match(r"^\s*(toolchain\s+go|go\s+)(\d+\.\d+(?:\.\d+)?)", l)
            if not m: continue
            v = m.group(2); mm = major_minor(v, 2); directive = m.group(1).strip()
            if mm in V["go"] and len(vtuple(v)) == 3 and vlt(v, V["go"][mm]): self.add(rel, i + 1, "go-toolchain", v, V["go"][mm], "high", "auto", f"{directive} directive below fixed")
            elif mm and vlt(mm, V["go_eol_below"]) and directive == "go": self.add(rel, i + 1, "go-toolchain", v, V["go"]["1.26"], "medium", "manual", "go directive on an unsupported line; GOTOOLCHAIN=auto will pick whatever CI has installed")

    def scan_python_deps(self, rel):
        V = self.V; base = os.path.basename(rel)
        pat = re.compile(r"""^\s*(?:name\s*=\s*)?["']?certifi["']?\s*(?:==|>=|~=|=)\s*["']?(\d{4}\.\d{1,2}\.\d{1,2})""")
        for i, l in enumerate(open(os.path.join(self.repo, rel), errors="replace")):
            m = pat.match(l) or re.match(r'^\s*version\s*=\s*"(\d{4}\.\d{1,2}\.\d{1,2})"', l) if "lock" in base and getattr(self, "_in_certifi", False) else pat.match(l)
            if "lock" in base:
                if re.match(r'^\s*name\s*=\s*"?certifi"?\s*$', l) or re.match(r'^\s*"certifi":\s*\{', l): self._in_certifi = True; continue
                if self._in_certifi:
                    mv = re.match(r'^\s*"?version"?\s*[=:]\s*"(\d{4}\.\d{1,2}\.\d{1,2})"', l)
                    if mv:
                        self._in_certifi = False
                        if vlt(mv.group(1), V["certifi"]): self.add(rel, i + 1, "python-dep", mv.group(1), V["certifi"], "high", "tool", self.lock_cmd(base))
                    elif re.match(r"^\s*\[\[|^\s*\}", l): self._in_certifi = False
                continue
            if m and vlt(m.group(1), V["certifi"]): self.add(rel, i + 1, "python-dep", m.group(1), V["certifi"], "high", "auto", f"certifi pin in {base}")
            if re.match(r"^\s*certifi\s*$", l): self.add(rel, i + 1, "python-dep", "unpinned", V["certifi"], "low", "auto", "unpinned certifi; add a floor so old caches can't satisfy it")

    @staticmethod
    def lock_cmd(base):
        return {"uv.lock": "uv lock --upgrade-package certifi", "poetry.lock": "poetry update certifi", "Pipfile.lock": "pipenv update certifi"}.get(base, "regenerate lockfile")

    def scan_cargo_lock(self, rel):
        name = None
        for i, l in enumerate(open(os.path.join(self.repo, rel), errors="replace")):
            m = re.match(r'^name\s*=\s*"([^"]+)"', l)
            if m: name = m.group(1); continue
            m = re.match(r'^version\s*=\s*"([^"]+)"', l)
            if m and name in ("webpki-roots", "webpki-root-certs", "rustls-webpki") and vlt(m.group(1), self.V[name]):
                self.add(rel, i + 1, "cargo-dep", f"{name} {m.group(1)}", self.V[name], "high", "tool", f"cargo update -p {name}")

    def scan_composer(self, rel):
        try: d = json.load(open(os.path.join(self.repo, rel)))
        except Exception: return
        V = self.V
        pkgs = d.get("packages", []) + d.get("packages-dev", []) if "lock" in rel else []
        for p in pkgs:
            if p.get("name") == "composer/ca-bundle":
                v = p.get("version", "").lstrip("v"); mm = major_minor(v, 2); fixed = V["composer/ca-bundle"].get(mm) or V["composer/ca-bundle"]["1.6"]
                if vlt(v, fixed): self.add(rel, 0, "composer-dep", f"composer/ca-bundle {v}", fixed, "high", "tool", "composer update composer/ca-bundle")
        req = (d.get("require") or {}).get("php") if "lock" not in rel else (d.get("platform") or {}).get("php")
        if req:
            m = re.search(r"(\d+\.\d+)", req)
            if m and (m.group(1) in V["php_eol"] or m.group(1).split(".")[0] in V["php_eol"]): self.add(rel, 0, "php-version", req, "^8.3", "critical", "manual", "php constraint allows an EOL line (PHP2Shell unpatched)")

    def scan_mix_lock(self, rel):
        for i, l in enumerate(open(os.path.join(self.repo, rel), errors="replace")):
            m = re.match(r'^\s*"castore":.*?"castore",\s*"([\d.]+)"', l)
            if m and vlt(m.group(1), self.V["castore"]): self.add(rel, i + 1, "mix-dep", f"castore {m.group(1)}", self.V["castore"], "high", "tool", "mix deps.update castore")
            if '"certifi":' in l: self.add(rel, i + 1, "mix-dep", "erlang certifi", "pending", "medium", "manual", "erlang-certifi fix still pending upstream; prefer castore or :public_key.cacerts_get()")

    def scan_ci(self, rel):
        V = self.V
        for i, l in enumerate(open(os.path.join(self.repo, rel), errors="replace")):
            m = re.match(r"""^\s*(go-version|node-version|php-version|python-version|deno-version|bun-version):\s*["']?([^"'\s#]+)""", l)
            if not m: continue
            k, v = m.groups()
            if "$" in v or v in ("stable", "latest"): continue
            if k == "go-version":
                mm = major_minor(v, 2)
                if mm in V["go"] and (len(vtuple(v)) < 3 or vlt(v, V["go"][mm])): self.add(rel, i + 1, "ci-version", v, V["go"][mm], "high", "auto", "setup-go pin" + ("" if len(vtuple(v)) >= 3 else " (floating minor: resolves to latest at run time, but runner caches can lag; pin)"))
                elif mm and vlt(mm, V["go_eol_below"]): self.add(rel, i + 1, "ci-version", v, V["go"]["1.26"], "high", "manual", "setup-go on an unsupported line")
            elif k == "node-version":
                maj = major_minor(v, 1)
                if maj in V["node_eol"]: self.add(rel, i + 1, "ci-version", v, V["node"]["24"], "high", "manual", "setup-node on an EOL line")
                elif maj in V["node"] and (len(vtuple(v)) < 3 or vlt(v, V["node"][maj])): self.add(rel, i + 1, "ci-version", v, V["node"][maj], "high", "auto", "setup-node pin")
            elif k == "php-version":
                mm = major_minor(v, 2)
                if mm in V["php"] and (len(vtuple(v)) < 3 or vlt(v, V["php"][mm])): self.add(rel, i + 1, "ci-version", v, V["php"][mm], "critical", "auto", "setup-php pin (PHP2Shell)")
                elif mm in V["php_eol"]: self.add(rel, i + 1, "ci-version", v, V["php"]["8.3"], "critical", "manual", "setup-php on an EOL line")
            elif k == "bun-version": self.add(rel, i + 1, "bun", v, "—", "medium", "manual", "CI uses Bun; no fixed release yet")
            m2 = re.search(r"\bpip\s+install\b(?!.*certifi)", l)
        # images used by jobs
        self.scan_compose_or_k8s(rel) if re.search(r"^\s*(container|image):", open(os.path.join(self.repo, rel), errors="replace").read(), re.M) else None

    def scan_vendored_ca(self, rel):
        txt = open(os.path.join(self.repo, rel), errors="replace").read()
        hits = [r for r in self.V["bad_roots"] + self.V["bad_intermediates"] if r in txt]
        if hits: self.add(rel, 0, "vendored-ca", ", ".join(hits), "curl cacert.pem ≥ 2026-10-20", "critical", "manual", "vendored CA bundle still trusts the compromised chain; replace with a current bundle or stop vendoring")

    def scan_wp_version(self, rel):
        m = re.search(r"\$wp_version\s*=\s*'([\d.]+)'", open(os.path.join(self.repo, rel), errors="replace").read())
        if m:
            v = m.group(1); mm = major_minor(v, 2); fixed = self.V["wordpress"].get(mm)
            if fixed is None or vlt(v, fixed): self.add(rel, 0, "wordpress-version", v, fixed or "7.1.2", "critical", "manual", "WordPress core below the fixed release (CVE-2026-87902 / wp2shell); upgrade core and check PHP")

    def scan_runtime_txt(self, rel):
        for i, l in enumerate(open(os.path.join(self.repo, rel), errors="replace")):
            if l.strip().startswith("python-"): self.add(rel, i + 1, "python-dep", l.strip(), "ensure certifi ≥ " + self.V["certifi"] + " in requirements", "low", "manual", "Heroku-style runtime; certifi comes from requirements")

    DISPATCH = [
        (re.compile(r"(^|/)(Dockerfile(\..*)?|Containerfile|.*\.dockerfile)$"), "scan_dockerfile"),
        (re.compile(r"(^|/)(docker-)?compose[^/]*\.ya?ml$|(^|/)(k8s|kube|manifests|deploy|charts)/.*\.ya?ml$"), "scan_compose_or_k8s"),
        (re.compile(r"(^|/)\.(nvmrc|node-version)$"), "scan_nvmrc"),
        (re.compile(r"(^|/)\.tool-versions$"), "scan_tool_versions"),
        (re.compile(r"(^|/)package\.json$"), "scan_package_json"),
        (re.compile(r"(^|/)go\.mod$"), "scan_go_mod"),
        (re.compile(r"(^|/)(requirements[^/]*\.txt|constraints[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile\.lock)$"), "scan_python_deps"),
        (re.compile(r"(^|/)Cargo\.lock$"), "scan_cargo_lock"),
        (re.compile(r"(^|/)composer\.(json|lock)$"), "scan_composer"),
        (re.compile(r"(^|/)mix\.lock$"), "scan_mix_lock"),
        (re.compile(r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.yml|bitbucket-pipelines\.yml|\.buildkite/[^/]+\.ya?ml|\.circleci/config\.yml)$"), "scan_ci"),
        (re.compile(r"\.(pem|crt|cer|bundle)$|(^|/)(cacert|ca-bundle|ca-certificates)[^/]*$"), "scan_vendored_ca"),
        (re.compile(r"(^|/)wp-includes/version\.php$"), "scan_wp_version"),
        (re.compile(r"(^|/)runtime\.txt$"), "scan_runtime_txt"),
    ]

    def scan_file(self, rel):
        self._in_certifi = False
        for pat, fn in self.DISPATCH:
            if pat.search(rel):
                try: getattr(self, fn)(rel)
                except Exception as e: self.add(rel, 0, "scan-error", "", "", "info", "none", f"{fn}: {e}")
                return

    def walk(self):
        for root, dirs, files in os.walk(self.repo):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "vendor", "site-packages", "target", "dist", "build", ".cache")]
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), self.repo)
                self.scan_file(rel)

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo"); ap.add_argument("--files", nargs="*"); ap.add_argument("--versions", default=os.path.join(HERE, "versions.json")); ap.add_argument("--json")
    a = ap.parse_args()
    V = json.load(open(a.versions)); s = Scanner(os.path.abspath(a.repo), V)
    if a.files:
        for f in a.files: s.scan_file(f)
    else: s.walk()
    s.out.sort(key=lambda f: (SEV.get(f["severity"], 9), f["file"], f["line"]))
    if a.json:
        json.dump({"repo": s.repo, "findings": s.out}, open(a.json, "w"), indent=1)
    counts = {}
    for f in s.out: counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"{s.repo}: {len(s.out)} findings " + " ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: SEV.get(kv[0], 9))))
    for f in s.out:
        if f["severity"] != "info": print(f"  [{f['severity']:8}] {f['file']}:{f['line']}  {f['kind']}  {f['current']} -> {f['fixed']}  ({f['fix']}) {f['note']}")
    return 1 if any(f["severity"] in ("critical", "high") for f in s.out) else 0

if __name__ == "__main__":
    sys.exit(main())
