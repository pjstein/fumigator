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
	return []string{"runtime", "name", "created", "state", "version", "bad_roots"}
}
func (containerVMs) Doc() string {
	return "Linux VMs behind podman machine, Docker Desktop and colima: creation time, state, and which compromised roots their trust store still lists (podman: read via machine ssh; docker: via a fresh alpine container, which also proves the pulled base is current)"
}
func (containerVMs) Platforms() []string { return []string{"darwin"} }
func (containerVMs) Slow() bool          { return false }

func (containerVMs) Collect(opt table.Options) ([]table.Row, error) {
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
				bad := "unknown (vm not running)"
				if m.Running {
					// Fedora CoreOS keeps its bundle here; read it inside the VM
					if out, ok := table.Sh("podman", "machine", "ssh", m.Name, "cat /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem 2>/dev/null || cat /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null || cat /etc/ssl/certs/ca-certificates.crt"); ok {
						bad = strings.Join(table.ContainsAny([]byte(out), opt.BadRoots), ";")
					}
				}
				rows = append(rows, table.Row{"runtime": "podman", "name": m.Name, "created": m.Created, "state": st, "version": table.FirstVersion(v), "bad_roots": bad})
			}
		}
	}
	if out, ok := table.Sh("docker", "version", "--format", "{{.Server.Version}}"); ok && out != "" && !strings.Contains(out, "Cannot connect") {
		bad := "unknown"
		if c, ok := table.Sh("docker", "run", "--rm", "alpine:latest", "cat", "/etc/ssl/certs/ca-certificates.crt"); ok {
			bad = strings.Join(table.ContainsAny([]byte(c), opt.BadRoots), ";")
		}
		rows = append(rows, table.Row{"runtime": "docker", "name": "desktop", "created": "", "state": "running", "version": table.FirstVersion(out), "bad_roots": bad})
	} else if table.Exists("/Applications/Docker.app") {
		v, _ := table.Sh("plutil", "-extract", "CFBundleShortVersionString", "raw", "/Applications/Docker.app/Contents/Info.plist")
		rows = append(rows, table.Row{"runtime": "docker", "name": "desktop", "created": "", "state": "stopped", "version": table.FirstVersion(v), "bad_roots": "unknown (not running)"})
	}
	if out, ok := table.Sh("colima", "list", "--json"); ok {
		for l := range strings.SplitSeq(out, "\n") {
			var m struct{ Name, Status string }
			if json.Unmarshal([]byte(l), &m) == nil && m.Name != "" {
				rows = append(rows, table.Row{"runtime": "colima", "name": m.Name, "created": "", "state": strings.ToLower(m.Status), "version": "", "bad_roots": "unknown"})
			}
		}
	}
	return rows, nil
}

func init() { table.Register(containerVMs{}) }
