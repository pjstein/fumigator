package collectors

import (
	"encoding/json"
	"strings"

	"github.com/pjstein/fumigator/internal/host/table"
)

// containerVMs: the Linux VMs behind podman machine, Docker Desktop and colima. Each has its
// own distro trust store that the host's updates never touch; an old VM image keeps the roots.
type containerVMs struct{}

func (containerVMs) Name() string { return "container_vms" }
func (containerVMs) Columns() []string {
	return []string{"runtime", "name", "created", "state", "version"}
}
func (containerVMs) Doc() string {
	return "Linux VMs behind podman machine, Docker Desktop and colima, with when they were created and whether they run"
}
func (containerVMs) Platforms() []string { return []string{"darwin"} }
func (containerVMs) Slow() bool          { return false }

func (containerVMs) Collect(_ table.Options) ([]table.Row, error) {
	var rows []table.Row
	if out, ok := table.Sh("podman", "machine", "list", "--format", "json"); ok {
		var ms []struct {
			Name, Created, LastUp string
			Running, Starting     bool
		}
		if json.Unmarshal([]byte(out), &ms) == nil {
			for _, m := range ms {
				st := "stopped"
				if m.Running {
					st = "running"
				} else if m.Starting {
					st = "starting"
				}
				v, _ := table.Sh("podman", "--version")
				rows = append(rows, table.Row{"runtime": "podman", "name": m.Name, "created": m.Created, "state": st, "version": table.FirstVersion(v)})
			}
		}
	}
	if out, ok := table.Sh("docker", "version", "--format", "{{.Server.Version}}"); ok && out != "" && !strings.Contains(out, "Cannot connect") {
		rows = append(rows, table.Row{"runtime": "docker", "name": "desktop", "created": "", "state": "running", "version": table.FirstVersion(out)})
	} else if table.Exists("/Applications/Docker.app") {
		v, _ := table.Sh("plutil", "-extract", "CFBundleShortVersionString", "raw", "/Applications/Docker.app/Contents/Info.plist")
		rows = append(rows, table.Row{"runtime": "docker", "name": "desktop", "created": "", "state": "stopped", "version": table.FirstVersion(v)})
	}
	if out, ok := table.Sh("colima", "list", "--json"); ok {
		for l := range strings.SplitSeq(out, "\n") {
			var m struct{ Name, Status string }
			if json.Unmarshal([]byte(l), &m) == nil && m.Name != "" {
				rows = append(rows, table.Row{"runtime": "colima", "name": m.Name, "created": "", "state": strings.ToLower(m.Status), "version": ""})
			}
		}
	}
	return rows, nil
}

func init() { table.Register(containerVMs{}) }
