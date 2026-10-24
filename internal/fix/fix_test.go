package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pjstein/fumigator/internal/engine"
	"github.com/pjstein/fumigator/internal/findings"
	"github.com/pjstein/fumigator/internal/pack"
)

func emudhra(t *testing.T) *pack.Pack {
	t.Helper()
	p, err := pack.Load(filepath.Join("..", "..", "packs", "emudhra-ca-2026-10"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A file with no final newline keeps having none; a file with one keeps it.
func TestFlushKeepsFinalNewlineState(t *testing.T) {
	p := emudhra(t)
	dir := t.TempDir()
	write(t, dir, "Dockerfile", "FROM debian:bookworm-slim\nCMD [\"true\"]")
	if err := os.Mkdir(filepath.Join(dir, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "b/Dockerfile", "FROM debian:bookworm-slim\nCMD [\"true\"]\n")
	rep := engine.ScanFiles(p, dir, []string{"Dockerfile", "b/Dockerfile"}, engine.Options{}, nil)
	res := Run(p, rep, Options{Apply: true})
	if len(res.Edits) < 2 {
		t.Fatalf("want an edit in each Dockerfile, got %+v", res.Edits)
	}
	if got := read(t, dir, "Dockerfile"); strings.HasSuffix(got, "\n") || !strings.Contains(got, "ca-certificates") {
		t.Errorf("Dockerfile gained a final newline or lost the edit:\n%q", got)
	}
	if got := read(t, dir, "b/Dockerfile"); !strings.HasSuffix(got, "\"]\n") {
		t.Errorf("b/Dockerfile lost its final newline:\n%q", got)
	}
}

// Without --run-tools the lock is not regenerated, so a pin raised beside it is rolled back.
func TestPinRolledBackWhenToolsNotRun(t *testing.T) {
	p := emudhra(t)
	dir := t.TempDir()
	pyproject := "[project]\nname = \"x\"\ndependencies = [\n    \"certifi==2023.7.22\",\n]\n"
	write(t, dir, "pyproject.toml", pyproject)
	write(t, dir, "uv.lock", "version = 1\n\n[[package]]\nname = \"certifi\"\nversion = \"2023.7.22\"\n")
	rep := engine.ScanFiles(p, dir, []string{"pyproject.toml", "uv.lock"}, engine.Options{}, nil)
	res := Run(p, rep, Options{Apply: true})
	if got := read(t, dir, "pyproject.toml"); got != pyproject {
		t.Errorf("pin not rolled back:\n%s", got)
	}
	for _, e := range res.Edits {
		if e.File == "pyproject.toml" {
			t.Errorf("rolled-back edit still reported: %+v", e)
		}
	}
	lock := false
	for _, f := range res.Manual {
		if f.File == "uv.lock" && strings.Contains(f.Note, "run: `") {
			lock = true
		}
	}
	if !lock {
		t.Errorf("uv.lock should be a manual item with its command, got %+v", res.Manual)
	}
}

// Manual items are decisions outside the PR: plain bullets, never unchecked task boxes.
func TestManualSectionHasNoTaskBoxes(t *testing.T) {
	s := ManualSection([]findings.Finding{{Severity: "high", File: "Dockerfile", Line: 1, Detector: "node-image-line", State: "eol", Current: "node:18"}})
	if strings.Contains(s, "[ ]") || !strings.Contains(s, "- **high** `Dockerfile:1`") {
		t.Errorf("unexpected manual section:\n%s", s)
	}
}
