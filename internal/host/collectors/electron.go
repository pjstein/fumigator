package collectors

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pjstein/fumigator/internal/host/table"
)

// electronApps: desktop apps built on Electron, which ship Chromium's root store and do not
// receive Chrome's CRLSet updates, so only an app update removes the compromised roots.
type electronApps struct{}

func (electronApps) Name() string      { return "electron_apps" }
func (electronApps) Columns() []string { return []string{"app", "version", "major", "path"} }
func (electronApps) Doc() string {
	return "Electron-based apps in /Applications and ~/Applications with their Electron version"
}
func (electronApps) Platforms() []string { return []string{"darwin"} }
func (electronApps) Slow() bool          { return false }

func (electronApps) Collect(_ table.Options) ([]table.Row, error) {
	var rows []table.Row
	for _, dir := range []string{"/Applications", filepath.Join(table.Home(), "Applications")} {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".app") {
				continue
			}
			app := filepath.Join(dir, e.Name())
			fw := filepath.Join(app, "Contents", "Frameworks", "Electron Framework.framework")
			if !table.Exists(fw) {
				continue
			}
			v := ""
			// The framework's Info.plist carries the Electron version as CFBundleVersion;
			// some builds also set CFBundleShortVersionString. Try both plist locations.
			for _, pl := range []string{filepath.Join(fw, "Resources", "Info.plist"), filepath.Join(fw, "Versions", "A", "Resources", "Info.plist")} {
				if !table.Exists(pl) {
					continue
				}
				for _, key := range []string{"CFBundleShortVersionString", "CFBundleVersion"} {
					if out, ok := table.Sh("plutil", "-extract", key, "raw", pl); ok && table.FirstVersion(out) != "" {
						v = table.FirstVersion(out)
						break
					}
				}
				if v != "" {
					break
				}
			}
			if v == "" {
				v = "unknown"
			}
			rows = append(rows, table.Row{"app": strings.TrimSuffix(e.Name(), ".app"), "version": v, "major": table.Major(v), "path": app})
		}
	}
	return rows, nil
}

func init() { table.Register(electronApps{}) }
