package collectors

import (
	"regexp"
	"strings"

	"github.com/pjstein/fumigator/internal/host/table"
)

type brewPackages struct{}

func (brewPackages) Name() string      { return "brew_packages" }
func (brewPackages) Columns() []string { return []string{"name", "version"} }
func (brewPackages) Doc() string {
	return "Homebrew formulae and versions (date-style versions normalised to dotted)"
}
func (brewPackages) Platforms() []string { return nil }
func (brewPackages) Slow() bool          { return false }

var dateVer = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(_\d+)?$`)

// normalizeBrewVersion turns "2026-09-25_1" into "2026.09.25.1" so it compares against a table.
func normalizeBrewVersion(v string) string {
	if dateVer.MatchString(v) {
		return strings.NewReplacer("-", ".", "_", ".").Replace(v)
	}
	return v
}

func (brewPackages) Collect(_ table.Options) ([]table.Row, error) {
	out, ok := table.Sh("brew", "list", "--versions")
	if !ok {
		return nil, nil
	}
	var rows []table.Row
	for l := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			rows = append(rows, table.Row{"name": f[0], "version": normalizeBrewVersion(f[len(f)-1])})
		}
	}
	return rows, nil
}

func init() { table.Register(brewPackages{}) }
