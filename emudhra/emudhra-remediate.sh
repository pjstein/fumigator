#!/usr/bin/env bash
# emudhra-remediate.sh — audit and fix a Mac's developer toolchain for the
# eMudhra intermediate CA compromise (Oct 17 2026) and PHP2Shell (Oct 21 2026).
#
#   ./emudhra-remediate.sh                 dry run: detect what's installed, print the plan
#   ./emudhra-remediate.sh --apply         run the plan (sudo steps prompt for your password)
#   ./emudhra-remediate.sh --apply --brew-all        also run a full `brew upgrade`
#   ./emudhra-remediate.sh --venv-roots "$HOME/src $HOME/work"   where to look for Python venvs
#
# Works on Apple's stock bash 3.2. Changes nothing without --apply. Logs to ./emudhra-remediate.log.
# Fixed-version table from https://emudhra.we-have-a-problem.com/#developers (as of 2026-10-22)
# and https://www.php.net/archive/2026.php#2026-10-21-5. Re-check that page: Bun and Erlang certifi
# were still pending when this was written.

set -u
APPLY=0; BREW_ALL=0
VENV_ROOTS="$HOME/source $HOME/src $HOME/code $HOME/dev $HOME/projects $HOME/work $HOME/repos $HOME/git"
LOG="$(pwd)/emudhra-remediate.log"
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --brew-all) BREW_ALL=1 ;;
    --venv-roots) shift; VENV_ROOTS="$1" ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1"; exit 2 ;;
  esac; shift
done

# ---------- fixed versions ----------
BREW_CA=2026-09-25_1
NODE_22=22.23.4; NODE_24=24.22.1; NODE_26=26.12.1
GO_126=1.26.10; GO_127=1.27.3
CERTIFI=2026.10.19; PIP=26.2.2; UV=0.13.4; PIXI=0.82.1
RUSTUP=1.29.2; DENO=2.9.8; MISE=2026.10.17; CLAUDE=2.1.303
PHP_82=8.2.35; PHP_83=8.3.36; PHP_84=8.4.27; PHP_85=8.5.12
ELECTRON_42=42.11.16; ELECTRON_43=43.8.1; ELECTRON_44=44.9.1
BAD=https://dv-g3b-emudhra.we-have-a-problem.com/
BAD2=https://dv-g3b-aaa-emudhra.we-have-a-problem.com/

# ---------- helpers ----------
NPLAN=0; NFIX=0; NWARN=0
say()  { printf '%s\n' "$*" | tee -a "$LOG"; }
hdr()  { say ""; say "== $* =="; }
ok()   { say "  ok    $*"; }
warn() { say "  WARN  $*"; NWARN=$((NWARN+1)); }
manual(){ say "  TODO  $*"; NWARN=$((NWARN+1)); }
# plan "what" "cmd": print in dry run, execute with --apply
plan() {
  NPLAN=$((NPLAN+1))
  if [ "$APPLY" = 1 ]; then
    say "  RUN   $1"; say "        \$ $2"
    if bash -c "$2" >>"$LOG" 2>&1; then NFIX=$((NFIX+1)); else warn "failed: $1 (see $LOG)"; fi
  else
    say "  PLAN  $1"; say "        \$ $2"
  fi
}
have() { command -v "$1" >/dev/null 2>&1; }
# vlt A B : true if version A < version B (numeric, dotted, up to 4 parts; strips leading v / trailing junk)
vlt() {
  awk -v a="$1" -v b="$2" 'BEGIN{
    gsub(/^[vV]/,"",a); gsub(/^[vV]/,"",b); gsub(/[^0-9.].*$/,"",a); gsub(/[^0-9.].*$/,"",b)
    n=split(a,A,"."); m=split(b,B,".")
    for(i=1;i<=4;i++){x=(i<=n)?A[i]+0:0; y=(i<=m)?B[i]+0:0; if(x<y)exit 0; if(x>y)exit 1}
    exit 1 }'
}
fetches() { "$@" >/dev/null 2>&1; }   # exit 0 = client fetched the bad-chain page = still trusts

: > "$LOG"
say "emudhra-remediate.sh  $(date)  mode=$([ "$APPLY" = 1 ] && echo APPLY || echo DRY-RUN)"
[ "$(uname)" = Darwin ] || { say "This script is for macOS."; exit 1; }

# ---------- 1. macOS ----------
hdr "macOS $(sw_vers -productVersion)"
if softwareupdate -l 2>&1 | grep -q 'Software Update found'; then
  manual "macOS updates are available. Install from System Settings > General > Software Update and restart (sudo softwareupdate -ia --restart)."
else ok "no pending macOS updates"; fi

n1=$(grep -c 'emSign ECC Root CA - G3' /etc/ssl/cert.pem 2>/dev/null); n2=$(grep -c 'AAA Certificate Services' /etc/ssl/cert.pem 2>/dev/null)
if [ "${n1:-0}" -gt 0 ] || [ "${n2:-0}" -gt 0 ]; then
  plan "strip emSign G3 + AAA roots from /etc/ssl/cert.pem (used by Apple's curl/git/python3/perl/ruby/openssl; backup at cert.pem.bak)" \
    "sudo cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.bak && sudo awk '/^(###|===) /{skip=0} /^=== .*\\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)\$/{skip=1} !skip' /etc/ssl/cert.pem.bak | sudo tee /etc/ssl/cert.pem >/dev/null"
else ok "/etc/ssl/cert.pem no longer contains the affected roots"; fi

if [ -x /usr/bin/python3 ] && /usr/bin/python3 -c 'import sysconfig' 2>/dev/null; then
  SC="$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' 2>/dev/null)/sitecustomize.py"
  if grep -qs PIP_CERT "$SC"; then ok "Apple python3 pip already pinned to /etc/ssl/cert.pem"
  elif case "$SC" in /Applications/Xcode.app/*|/Library/Developer/CommandLineTools/*) true;; *) false;; esac; then
    manual "Apple python3 lives inside a sealed bundle ($SC); if you use its pip3, add  export PIP_CERT=/etc/ssl/cert.pem  to your shell profile"
  else plan "point Apple python3's pip at the system bundle (its vendored certifi is stale)" \
    "echo 'import os; os.environ.setdefault(\"PIP_CERT\", \"/etc/ssl/cert.pem\")' | sudo tee -a '$SC' >/dev/null && sudo chmod 644 '$SC'"; fi
fi

# ---------- 2. Homebrew ----------
hdr "Homebrew"
if have brew; then
  BP="$(brew --prefix)"
  cav="$(brew list --versions ca-certificates 2>/dev/null | awk '{print $2}')"
  if [ -z "$cav" ] || vlt "$(echo "$cav" | tr -d '_' | tr - .)" "$(echo "$BREW_CA" | tr -d '_' | tr - .)"; then
    plan "update Homebrew bundle + TLS-linked basics" "brew update && brew upgrade ca-certificates openssl@3 curl git"
  else ok "ca-certificates $cav"; fi
  [ "$BREW_ALL" = 1 ] && plan "upgrade all Homebrew packages" "brew upgrade"
  case "$(command -v curl)" in /usr/bin/*) warn "the curl on your PATH is Apple's; Homebrew's is at $BP/opt/curl/bin (add to PATH to prefer it)";; esac
else warn "Homebrew not found; skipping"; fi

# ---------- 3. Node ----------
hdr "Node.js"
node_target() { case "$1" in 22) echo "$NODE_22";; 24) echo "$NODE_24";; 26) echo "$NODE_26";; *) echo "";; esac; }
NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
if [ -d "$NVM_DIR/versions/node" ]; then
  def="$(cat "$NVM_DIR/alias/default" 2>/dev/null)"
  for d in "$NVM_DIR"/versions/node/v*; do
    v="${d##*/v}"; maj="${v%%.*}"; t="$(node_target "$maj")"
    if [ -z "$t" ]; then warn "nvm node $v: major $maj has no fixed release (EOL). Move projects off it: nvm uninstall $v"
    elif vlt "$v" "$t"; then
      plan "nvm: install node $t beside $v" ". '$NVM_DIR/nvm.sh' && nvm install $t"
      case "$def" in "$v"|"$maj"|"lts/*"|"") plan "nvm: make $t the default" ". '$NVM_DIR/nvm.sh' && nvm alias default $t";; esac
    else ok "nvm node $v"; fi
  done
  say "        after installing: nvm uninstall <old> for versions nothing pins, and update .nvmrc files in repos"
fi
if have fnm; then for v in $(fnm ls 2>/dev/null | grep -o 'v[0-9][0-9.]*'); do maj="${v#v}"; maj="${maj%%.*}"; t="$(node_target "$maj")"
  if [ -z "$t" ]; then warn "fnm node $v: EOL major, no fix"; elif vlt "$v" "$t"; then plan "fnm: install node $t" "fnm install $t && fnm default $t"; else ok "fnm node $v"; fi; done; fi
if have volta; then v="$(volta list node --format plain 2>/dev/null | grep -o 'node@[0-9.]*' | head -1 | cut -d@ -f2)"; [ -n "$v" ] && { maj="${v%%.*}"; t="$(node_target "$maj")"
  if [ -z "$t" ]; then warn "volta node $v: EOL major"; elif vlt "$v" "$t"; then plan "volta: install node $t" "volta install node@$t"; else ok "volta node $v"; fi; }; fi
if have brew && brew list --versions node >/dev/null 2>&1; then v="$(brew list --versions node | awk '{print $2}')"; maj="${v%%.*}"; t="$(node_target "$maj")"
  [ -n "$t" ] && vlt "$v" "$t" && plan "brew: upgrade node" "brew upgrade node"; fi
have node || say "  --    no node found"

# ---------- 4. Python ----------
hdr "Python (certifi >= $CERTIFI, pip >= $PIP in every interpreter and venv)"
PYS=""
if have pyenv; then for v in $(pyenv versions --bare 2>/dev/null); do p="$(pyenv root)/versions/$v/bin/python"; [ -x "$p" ] && PYS="$PYS $p"; done; fi
if have brew; then
  bpy="$(brew list --formula 2>/dev/null | grep -E '^python@3\.[0-9]+$' | tr '\n' ' ')"
  [ -n "$bpy" ] && plan "upgrade Homebrew Pythons (PEP 668 blocks pip here; the formula ships fixed pip/certifi)" "brew upgrade $bpy"
fi
have uv && say "  --    uv-managed interpreters skipped: their venvs take certifi from each project's lockfile (the repo scanner covers that)"
for p in $PYS; do
  if ! "$p" -c 'import ssl' >/dev/null 2>&1; then manual "$p was built without the ssl module (cannot reach PyPI at all): pyenv uninstall it, or rebuild with pyenv install <same minor, latest patch>"; continue; fi
  cv="$("$p" -c 'import certifi; print(certifi.__version__)' 2>/dev/null)"
  pv="$("$p" -m pip --version 2>/dev/null | awk '{print $2}')"
  [ -z "$pv" ] && { warn "$p has no pip; skipping"; continue; }
  if [ -z "$cv" ] || vlt "$cv" "$CERTIFI" || vlt "$pv" "$PIP"; then
    plan "upgrade certifi/pip in $p (certifi ${cv:-absent}, pip $pv)" "'$p' -m pip install -q -U certifi pip"
  else ok "$p (certifi $cv, pip $pv)"; fi
done
# venvs
nv=0
for root in $VENV_ROOTS; do [ -d "$root" ] || continue
  for cfg in $(find "$root" -maxdepth 6 -name pyvenv.cfg -not -path '*/node_modules/*' 2>/dev/null); do
    vp="$(dirname "$cfg")/bin/python"; [ -x "$vp" ] || continue; nv=$((nv+1))
    "$vp" -c 'import ssl' >/dev/null 2>&1 || { manual "venv $(dirname "$cfg") has no ssl module (built from a broken interpreter); recreate it"; continue; }
    cv="$("$vp" -c 'import certifi; print(certifi.__version__)' 2>/dev/null)"
    [ -n "$cv" ] && ! vlt "$cv" "$CERTIFI" && continue
    "$vp" -m pip --version >/dev/null 2>&1 || continue   # uv venvs often have no pip; certifi comes from the project lock
    plan "upgrade certifi/pip in venv $(dirname "$cfg") (certifi ${cv:-absent})" "'$vp' -m pip install -q -U certifi pip"
  done
done
say "  --    scanned $nv venvs under: $VENV_ROOTS (override with --venv-roots). uv/poetry projects: bump certifi in the lockfile instead."
have conda && plan "conda: update base certifi" "conda update -y -n base certifi ca-certificates"
if have uv; then v="$(uv --version | awk '{print $2}')"; vlt "$v" "$UV" && plan "uv $v -> $UV" "uv self update || brew upgrade uv" || ok "uv $v"; fi
if have pixi; then v="$(pixi --version | awk '{print $2}')"; vlt "$v" "$PIXI" && plan "pixi $v -> $PIXI" "pixi self-update" || ok "pixi $v"; fi

# ---------- 5. Go ----------
hdr "Go"
if have go; then v="$(go version | grep -o 'go[0-9][0-9.]*' | head -1 | sed 's/^go//')"
  case "$v" in 1.26*) t=$GO_126;; 1.27*) t=$GO_127;; *) t="";; esac
  if [ -z "$t" ]; then warn "go $v: not a supported line; move to $GO_127"
  elif vlt "$v" "$t"; then
    if have brew && brew list --versions go 2>/dev/null | grep -q " $t"; then warn "brew already has go $t but your shell runs $v: open a new terminal, or brew link --overwrite go"
    elif have brew && brew list --versions go >/dev/null 2>&1; then plan "go $v -> $t" "brew upgrade go"; else manual "go $v -> $t: install from https://go.dev/dl/"; fi
  else ok "go $v"; fi
  say "        on macOS Go verifies via the OS trust store; the new release matters for Linux builds, containers and CI (check go.mod toolchain lines / GOTOOLCHAIN)"
else say "  --    no go"; fi

# ---------- 6. Rust ----------
hdr "Rust"
if have rustup; then v="$(rustup --version 2>/dev/null | awk '{print $2}')"
  vlt "$v" "$RUSTUP" && plan "rustup $v -> $RUSTUP + toolchains" "rustup self update && rustup update" || ok "rustup $v"
  say "        projects using rustls: cargo update -p webpki-roots -p rustls-webpki in each repo (check cargo tree -i webpki-roots)"
fi

# ---------- 7. Java ----------
hdr "Java"
if have java; then
  if have brew && brew list --formula 2>/dev/null | grep -q '^openjdk'; then plan "upgrade Homebrew JDK(s)" "brew upgrade $(brew list --formula | grep '^openjdk' | tr '\n' ' ')"; fi
  [ -d "$HOME/.sdkman" ] && manual "sdkman: sdk list java, then sdk install java <fixed build> (17.0.21.0.2 / 21.0.13.0.2 / 25.0.5.0.2 / 27.0.1.0.2)"
  if have keytool; then
    bad_aliases="$(keytool -list -cacerts -storepass changeit 2>/dev/null | grep -iE 'emsigneccrootcag3|emsignroottlscag3|aaa ?certificate ?services|comodoaaa' | cut -d, -f1)"
    if [ -n "$bad_aliases" ]; then
      # aliases contain spaces ("comodoaaaca [jdk]"): build the command line by line, never word-split
      cmd=""; while IFS= read -r a; do [ -n "$a" ] && cmd="$cmd keytool -delete -cacerts -storepass changeit -alias '$a' &&"; done <<EOA
$bad_aliases
EOA
      plan "remove affected roots from the default JDK keystore (aliases: $(echo "$bad_aliases" | tr '\n' ';'))" "${cmd% &&}"
    else ok "default JDK keystore lists neither emSign G3 nor AAA Certificate Services (emSign G1/G2 roots are left in place on purpose)"; fi
    say "        other JDKs on this Mac: /usr/libexec/java_home -V ; repeat with JAVA_HOME=<path> keytool ..."
  fi
fi

# ---------- 8. Ruby / Perl ----------
hdr "Ruby / Perl"
if have brew && brew list --versions ruby >/dev/null 2>&1; then plan "upgrade Homebrew ruby + openssl" "brew upgrade ruby openssl@3"; fi
{ have rbenv || [ -d "$HOME/.rbenv" ]; } && manual "rbenv rubies link their own openssl: rbenv install <same version> after brew upgrade openssl@3, or RUBY_CONFIGURE_OPTS=--with-openssl-dir=\$(brew --prefix openssl@3)"
have gem && plan "update RubyGems" "gem update --system -q"
have cpanm && plan "Perl: update Mozilla::CA" "cpanm -q Mozilla::CA"

# ---------- 9. PHP / Composer (PHP2Shell + CA bundle) ----------
hdr "PHP"
if have php; then v="$(php -r 'echo PHP_VERSION;')"
  case "$v" in 8.2*) t=$PHP_82;; 8.3*) t=$PHP_83;; 8.4*) t=$PHP_84;; 8.5*) t=$PHP_85;; *) t="";; esac
  if [ -z "$t" ]; then warn "php $v: EOL line, no PHP2Shell fix from php.net; upgrade to 8.3+ (brew install php@8.3)"
  elif vlt "$v" "$t"; then
    if have brew; then plan "php $v -> $t (PHP2Shell CVE-2026-109618/109619)" "brew upgrade $(brew list --formula | grep '^php' | tr '\n' ' ') && (brew services restart php 2>/dev/null || true)"
    else manual "php $v -> $t: update via Herd / MAMP / your installer"; fi
  else ok "php $v"; fi
  for ini in $(php --ini 2>/dev/null | grep -o '/[^ ]*\.ini'); do
    grep -Eq '^\s*session\.upload_progress\.enabled\s*=\s*(1|On|true)' "$ini" 2>/dev/null && warn "$ini enables session.upload_progress (set 0 if you cannot update)"
  done
  have composer && plan "composer self-update" "composer self-update -q"
  say "        in each PHP project: composer update composer/ca-bundle   (>= 1.4.16 / 1.6.0)"
fi
[ -d "$HOME/Library/Application Support/Herd" ] && manual "Laravel Herd: Settings > PHP, update each installed version"
[ -d /Applications/MAMP ] && manual "MAMP: update from the app; retire bundled PHP < 8.2"
have ddev && plan "ddev: self-upgrade (then ddev restart in each project)" "ddev self-upgrade"

# ---------- 10. Other runtimes / CLIs ----------
hdr "Deno / Bun / mise / Claude Code"
if have deno; then v="$(deno --version | head -1 | awk '{print $2}')"; vlt "$v" "$DENO" && plan "deno $v -> $DENO" "deno upgrade" || ok "deno $v"; fi
if have bun; then warn "bun $(bun --version): no fixed release yet (https://github.com/oven-sh/bun/pull/46159). Avoid bun for public-internet fetches, or set NODE_EXTRA_CA_CERTS to a clean bundle."; fi
if have mise; then v="$(mise --version 2>/dev/null | awk '{print $1}')"; vlt "$v" "$MISE" && plan "mise $v -> $MISE" "mise self-update -y" || ok "mise $v"; fi
if have claude; then v="$(claude --version 2>/dev/null | awk '{print $1}')"; vlt "$v" "$CLAUDE" && plan "claude code $v -> $CLAUDE" "claude update" || ok "claude code $v"; fi
have elixir && manual "Elixir projects: mix deps.update castore (>= 1.0.22); erlang-certifi fix still pending"

# ---------- 11. Desktop apps (report only) ----------
hdr "Electron apps (need Electron >= $ELECTRON_42 / $ELECTRON_43 / $ELECTRON_44)"
for f in /Applications/*.app "$HOME"/Applications/*.app; do [ -d "$f" ] || continue
  pl="$f/Contents/Frameworks/Electron Framework.framework/Resources/Info.plist"
  [ -f "$pl" ] || pl="$f/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"
  [ -f "$pl" ] || continue
  ev="$(plutil -extract CFBundleShortVersionString raw "$pl" 2>/dev/null)"; [ -n "$ev" ] || continue
  maj="${ev%%.*}"; case "$maj" in 42) t=$ELECTRON_42;; 43) t=$ELECTRON_43;; 44) t=$ELECTRON_44;; *) t="";; esac
  if { [ -z "$t" ] && [ "$maj" -lt 42 ]; } || { [ -n "$t" ] && vlt "$ev" "$t"; }; then manual "$(basename "$f") on Electron $ev: update the app"; else ok "$(basename "$f") Electron $ev"; fi
done
[ -d "/Applications/Docker.app" ] && manual "Docker Desktop: check for updates; rebuild images from updated bases (see team doc, Step 5)"

# ---------- 12. verify ----------
hdr "Verify (STILL TRUSTS = that client fetched the compromised-chain test page)"
chk() { local l="$1"; shift; if fetches "$@"; then warn "$l STILL TRUSTS"; else ok "$l rejects"; fi; }
chk "/usr/bin/curl"       /usr/bin/curl -sSf --max-time 10 "$BAD"
chk "curl (PATH)"         curl -sSf --max-time 10 "$BAD"
chk "curl AAA cross-sign" curl -sSf --max-time 10 "$BAD2"
chk "/usr/bin/git"        /usr/bin/git ls-remote "$BAD"
have python3 && chk "python3 + certifi" python3 -c "import ssl,certifi,urllib.request as u; u.urlopen('$BAD',timeout=10,context=ssl.create_default_context(cafile=certifi.where()))"
have node    && chk "node"  node -e "fetch('$BAD').then(()=>process.exit(0),()=>process.exit(1))"
have deno    && chk "deno"  deno eval "await fetch('$BAD')"
have bun     && chk "bun"   bun -e "await fetch('$BAD')"
have ruby    && chk "ruby"  ruby -ropen-uri -e "URI.open('$BAD').read"
have php     && chk "php"   php -r "if(@file_get_contents('$BAD')===false) exit(1);"
have go      && chk "go"    sh -c "d=\$(mktemp -d) && cd \$d && go mod init x >/dev/null 2>&1 && printf 'package main\nimport \"net/http\"\nfunc main(){ if _,e:=http.Get(\"$BAD\"); e!=nil { panic(e) } }' > m.go && go run m.go"
have java    && chk "java"  sh -c "d=\$(mktemp -d) && cd \$d && printf 'public class T{public static void main(String[] a)throws Exception{new java.net.URL(\"$BAD\").openStream().close();}}' > T.java && java T.java"
curl -sSf --max-time 10 https://github.com >/dev/null 2>&1 || warn "curl can't reach github.com — check you didn't over-block"

say ""
if [ "$APPLY" = 1 ]; then say "Done: $NFIX of $NPLAN planned fixes applied, $NWARN items need you. Open a NEW terminal before re-running (PATH/nvm changes). Log: $LOG"
else say "Dry run: $NPLAN fixes planned, $NWARN items need you. Re-run with --apply to execute."; fi
