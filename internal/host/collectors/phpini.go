package collectors

import (
	"bufio"
	"os"
	"regexp"

	"github.com/pjstein/fumigator/internal/host/table"
)

type phpIni struct{}

func (phpIni) Name() string      { return "php_ini" }
func (phpIni) Columns() []string { return []string{"path", "upload_progress_enabled"} }
func (phpIni) Doc() string {
	return "ini files the installed PHP loads (php --ini) and whether session.upload_progress is enabled"
}
func (phpIni) Platforms() []string { return nil }
func (phpIni) Slow() bool          { return false }

var (
	iniPath = regexp.MustCompile(`/[^\s,]+\.ini`)
	iniOn   = regexp.MustCompile(`^\s*session\.upload_progress\.enabled\s*=\s*(1|On|on|true|True)\b`)
)

func (phpIni) Collect(_ table.Options) ([]table.Row, error) {
	out, ok := table.Sh("php", "--ini")
	if !ok {
		return nil, nil
	}
	var rows []table.Row
	seen := map[string]bool{}
	for _, p := range iniPath.FindAllString(out, -1) {
		if seen[p] {
			continue
		}
		seen[p] = true
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		enabled := "false"
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if iniOn.MatchString(sc.Text()) {
				enabled = "true"
			}
		}
		_ = f.Close() // read-only handle
		if sc.Err() != nil {
			continue
		}
		rows = append(rows, table.Row{"path": p, "upload_progress_enabled": enabled})
	}
	return rows, nil
}

func init() { table.Register(phpIni{}) }
