package collectors

import (
	"runtime"
	"strings"

	"github.com/pjstein/fumigator/internal/host/table"
)

type system struct{}

func (system) Name() string      { return "system" }
func (system) Columns() []string { return []string{"os", "version", "pending_updates"} }
func (system) Doc() string {
	return "OS name and version; whether OS updates are pending (macOS: softwareupdate -l, slow)"
}
func (system) Platforms() []string { return nil }
func (system) Slow() bool          { return true }

func (system) Collect(opt table.Options) ([]table.Row, error) {
	row := table.Row{"os": runtime.GOOS, "version": "", "pending_updates": "unknown"}
	if runtime.GOOS == "darwin" {
		v, _ := table.Sh("sw_vers", "-productVersion")
		row["version"] = v
		if !opt.Fast {
			if out, _ := table.Sh("softwareupdate", "-l"); strings.Contains(out, "Software Update found") {
				row["pending_updates"] = "true"
			} else {
				row["pending_updates"] = "false"
			}
		}
	}
	return []table.Row{row}, nil
}

func init() { table.Register(system{}) }
