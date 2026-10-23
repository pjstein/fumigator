package fix

import (
	"strings"
	"testing"
)

func TestCommandFor(t *testing.T) {
	chain := "uvx uv@0.13.4 lock --upgrade-package grpcio || poetry update grpcio || pdm update grpcio"
	cases := []struct{ cmd, file, want string }{
		{chain, "uv.lock", "uvx uv@0.13.4 lock --upgrade-package grpcio"},
		{chain, "a/b/poetry.lock", "poetry update grpcio"},
		{chain, "pdm.lock", "pdm update grpcio"},
		{chain, "Pipfile.lock", ""},
		{"uv lock --upgrade-package certifi", "poetry.lock", ""},
		{"cargo update -p webpki-roots", "Cargo.lock", "cargo update -p webpki-roots"},
		{"npm install -D electron@43.8.1", "package.json", "npm install -D electron@43.8.1"},
		{"go get golang.org/x/crypto/x509roots/fallback@latest && go mod tidy", "go.mod", "go get golang.org/x/crypto/x509roots/fallback@latest && go mod tidy"},
	}
	for _, c := range cases {
		if got := commandFor(c.cmd, c.file); got != c.want {
			t.Errorf("commandFor(%q, %q) = %q, want %q", c.cmd, c.file, got, c.want)
		}
	}
}

func TestLockRevision(t *testing.T) {
	if lockRevision([]byte("version = 1\nrevision = 3\nrequires-python = \">=3.12\"\n")) != "3" {
		t.Error("revision 3")
	}
	if lockRevision([]byte("version = 1\nrequires-python = \">=3.12\"\n")) != "1" {
		t.Error("no revision line means 1")
	}
}

func TestPackageOf(t *testing.T) {
	if packageOf("grpcio 1.80.0") != "grpcio" || packageOf("") != "" {
		t.Error("packageOf")
	}
}

func TestHashPinned(t *testing.T) {
	lines := []string{
		`certifi==2023.7.22 ; python_version >= "3.8" \`,
		`    --hash=sha256:aaaa \`,
		`    --hash=sha256:bbbb`,
		`grpcio==1.59.3`,
	}
	if !hashPinned(lines, 0) {
		t.Error("continuation with --hash must be hash-pinned")
	}
	if hashPinned(lines, 3) {
		t.Error("plain pin is not hash-pinned")
	}
}

func TestReplaceSection(t *testing.T) {
	body := "## Why\n\nx\n\n## Still needs a human (not changed by this PR)\n\n- [ ] old\n\n## Verify before merging\n\n- [ ] CI\n\n🤖 Generated"
	got := replaceSection(body, "Still needs a human (not changed by this PR)", "")
	if strings.Contains(got, "old") || !strings.Contains(got, "## Verify before merging") {
		t.Errorf("drop section:\n%s", got)
	}
	got = replaceSection(body, "Known caveats", "## Known caveats\n\n- c")
	if !strings.Contains(got, "## Known caveats\n\n- c\n\n## Verify before merging") && !strings.Contains(got, "## Known caveats\n\n- c\n## Verify") {
		t.Errorf("add section before verify:\n%s", got)
	}
}
