#!/usr/bin/env bash
# emudhra-audit.sh — read-only. Reports which tools on this Mac still trust the compromised intermediates.
BAD=https://dv-g3b-emudhra.we-have-a-problem.com/
BAD2=https://dv-g3b-aaa-emudhra.we-have-a-problem.com/

check() {  # name, command that fetches $BAD; success (exit 0) means the tool still trusts it
  if "$@" >/dev/null 2>&1; then printf '  %-28s STILL TRUSTS (fix needed)\n' "$1"; else printf '  %-28s ok (rejects)\n' "$1"; fi
}

echo "macOS: $(sw_vers -productVersion)"
echo "System bundle /etc/ssl/cert.pem contains emSign G3 root: $(grep -c 'emSign ECC Root CA - G3' /etc/ssl/cert.pem 2>/dev/null || echo 0)"
echo "System bundle contains AAA Certificate Services:      $(grep -c 'AAA Certificate Services' /etc/ssl/cert.pem 2>/dev/null || echo 0)"
echo
echo "Versions:"
for t in curl git go node python3 pip3 uv rustup cargo java ruby php composer deno bun mise elixir erl claude; do
  command -v $t >/dev/null 2>&1 && printf '  %-10s %s  (%s)\n' "$t" "$($t --version 2>&1 | head -1 | cut -c1-60)" "$(command -v $t)"
done
command -v brew >/dev/null && echo "  brew ca-certificates: $(brew list --versions ca-certificates 2>/dev/null)"
command -v python3 >/dev/null && echo "  certifi: $(python3 -c 'import certifi,sys; print(certifi.__version__, certifi.where())' 2>/dev/null || echo 'not installed')"
echo
echo "Live checks against $BAD (and the Sectigo cross-sign path):"
check "/usr/bin/curl (system)"   /usr/bin/curl -sS --max-time 10 "$BAD"
check "curl (PATH)"              curl -sS --max-time 10 "$BAD"
check "curl AAA cross-sign"      curl -sS --max-time 10 "$BAD2"
check "git (system)"             /usr/bin/git ls-remote "$BAD"
command -v python3 >/dev/null && check "python3 urllib"        python3 -c "import urllib.request as u; u.urlopen('$BAD', timeout=10)"
command -v python3 >/dev/null && check "python3 + certifi"     python3 -c "import ssl,certifi,urllib.request as u; u.urlopen('$BAD', timeout=10, context=ssl.create_default_context(cafile=certifi.where()))"
command -v node >/dev/null    && check "node"                  node -e "fetch('$BAD').then(r=>process.exit(0)).catch(()=>process.exit(1))"
command -v go >/dev/null      && check "go (net/http)"         sh -c "cd \$(mktemp -d) && go mod init x >/dev/null 2>&1 && printf 'package main\nimport \"net/http\"\nfunc main(){ if _,e:=http.Get(\"$BAD\"); e!=nil { panic(e) } }' > m.go && go run m.go"
command -v deno >/dev/null    && check "deno"                  deno eval "await fetch('$BAD')"
command -v bun >/dev/null     && check "bun"                   bun -e "await fetch('$BAD')"
command -v ruby >/dev/null    && check "ruby"                  ruby -ropen-uri -e "URI.open('$BAD').read"
command -v php >/dev/null     && check "php"                   php -r "if(file_get_contents('$BAD')===false) exit(1);"
command -v java >/dev/null    && check "java"                  sh -c "cd \$(mktemp -d) && printf 'public class T{public static void main(String[] a)throws Exception{new java.net.URL(\"$BAD\").openStream().close();}}' > T.java && java T.java"
