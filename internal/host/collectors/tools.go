package collectors

import (
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pjstein/fumigator/internal/host/table"
)

// tools: every known CLI on PATH, the version it reports, and which manager owns it.
type tools struct{}

func (tools) Name() string      { return "tools" }
func (tools) Columns() []string { return []string{"name", "version", "path", "manager"} }
func (tools) Doc() string {
	return "runtimes and CLIs on PATH with the version each reports (go, node, python3, php, java, uv, bun, deno, docker, podman, gcloud, aws, ...)"
}
func (tools) Platforms() []string { return nil }
func (tools) Slow() bool          { return false }

var toolSpecs = []struct {
	name string
	args []string
}{
	{"curl", []string{"--version"}}, {"git", []string{"--version"}}, {"go", []string{"version"}},
	{"node", []string{"--version"}}, {"python3", []string{"--version"}}, {"uv", []string{"--version"}},
	{"pixi", []string{"--version"}}, {"rustup", []string{"--version"}}, {"cargo", []string{"--version"}},
	{"java", []string{"-version"}}, {"ruby", []string{"--version"}}, {"gem", []string{"--version"}},
	{"php", []string{"-r", "echo PHP_VERSION;"}}, {"composer", []string{"--version"}},
	{"deno", []string{"--version"}}, {"bun", []string{"--version"}}, {"mise", []string{"--version"}},
	{"elixir", []string{"--version"}}, {"claude", []string{"--version"}}, {"codex", []string{"--version"}},
	{"cpanm", []string{"--version"}}, {"conda", []string{"--version"}}, {"ddev", []string{"--version"}},
	{"docker", []string{"--version"}}, {"podman", []string{"--version"}}, {"colima", []string{"version"}},
	{"gcloud", []string{"--version"}}, {"aws", []string{"--version"}}, {"az", []string{"version"}},
	{"nix", []string{"--version"}}, {"pnpm", []string{"--version"}}, {"yarn", []string{"--version"}},
	{"ollama", []string{"--version"}}, {"terraform", []string{"version"}}, {"pulumi", []string{"version"}},
	{"helm", []string{"version", "--short"}}, {"kubectl", []string{"version", "--client"}},
	{"gh", []string{"--version"}}, {"wget", []string{"--version"}}, {"R", []string{"--version"}},
	{"julia", []string{"--version"}}, {"dotnet", []string{"--version"}}, {"flutter", []string{"--version"}},
	{"dart", []string{"--version"}}, {"ghc", []string{"--version"}}, {"swift", []string{"--version"}},
}

func (tools) Collect(_ table.Options) ([]table.Row, error) {
	var rows []table.Row
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range toolSpecs {
		wg.Add(1)
		go func(name string, args []string) {
			defer wg.Done()
			p, err := exec.LookPath(name)
			if err != nil {
				return
			}
			out, _ := table.Sh(name, args...)
			v := table.FirstVersion(strings.SplitN(out, "\n", 2)[0])
			if name == "go" || name == "gcloud" || name == "aws" {
				v = table.FirstVersion(out)
			}
			real, _ := filepath.EvalSymlinks(p)
			mu.Lock()
			rows = append(rows, table.Row{"name": name, "version": v, "path": p, "manager": table.Manager(real)})
			mu.Unlock()
		}(s.name, s.args)
	}
	wg.Wait()
	return rows, nil
}

func init() { table.Register(tools{}) }
