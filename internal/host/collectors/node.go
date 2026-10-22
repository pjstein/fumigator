package collectors

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pjstein/fumigator/internal/host/table"
	"github.com/pjstein/fumigator/internal/version"
)

type nodeInstalls struct{}

func (nodeInstalls) Name() string { return "node_installs" }
func (nodeInstalls) Columns() []string {
	return []string{"manager", "version", "major", "path", "default", "superseded"}
}
func (nodeInstalls) Doc() string {
	return "Node runtimes under nvm, fnm, volta and Homebrew; superseded=true when a newer build of the same major is installed by the same manager"
}
func (nodeInstalls) Platforms() []string { return nil }
func (nodeInstalls) Slow() bool          { return false }

func (nodeInstalls) Collect(_ table.Options) ([]table.Row, error) {
	var rows []table.Row
	nvmDir := os.Getenv("NVM_DIR")
	if nvmDir == "" {
		nvmDir = filepath.Join(table.Home(), ".nvm")
	}
	def, _ := os.ReadFile(filepath.Join(nvmDir, "alias", "default"))
	if ents, err := os.ReadDir(filepath.Join(nvmDir, "versions", "node")); err == nil {
		for _, e := range ents {
			v := strings.TrimPrefix(e.Name(), "v")
			isDef := "false"
			if d := strings.TrimSpace(string(def)); d == v || d == "v"+v || d == table.Major(v) {
				isDef = "true"
			}
			rows = append(rows, table.Row{"manager": "nvm", "version": v, "major": table.Major(v),
				"path": filepath.Join(nvmDir, "versions", "node", e.Name(), "bin", "node"), "default": isDef})
		}
	}
	if out, ok := table.Sh("fnm", "ls"); ok {
		for _, m := range regexp.MustCompile(`v(\d+\.\d+\.\d+)`).FindAllStringSubmatch(out, -1) {
			rows = append(rows, table.Row{"manager": "fnm", "version": m[1], "major": table.Major(m[1]), "path": "", "default": "false"})
		}
	}
	if out, ok := table.Sh("volta", "list", "node", "--format", "plain"); ok {
		if m := regexp.MustCompile(`node@(\d+\.\d+\.\d+)`).FindStringSubmatch(out); m != nil {
			rows = append(rows, table.Row{"manager": "volta", "version": m[1], "major": table.Major(m[1]), "path": "", "default": "true"})
		}
	}
	if out, ok := table.Sh("brew", "list", "--versions", "node"); ok {
		if f := strings.Fields(out); len(f) >= 2 {
			rows = append(rows, table.Row{"manager": "brew", "version": f[1], "major": table.Major(f[1]), "path": "", "default": "false"})
		}
	}
	for _, r := range rows {
		r["superseded"] = "false"
		for _, o := range rows {
			if o["manager"] == r["manager"] && o["major"] == r["major"] && version.Less(r["version"], o["version"]) {
				r["superseded"] = "true"
				break
			}
		}
	}
	return rows, nil
}

func init() { table.Register(nodeInstalls{}) }
