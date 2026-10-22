package collectors

import (
	"strings"

	"github.com/pjstein/fumigator/internal/host/table"
)

type jdkAliases struct{}

func (jdkAliases) Name() string      { return "jdk_keystore_aliases" }
func (jdkAliases) Columns() []string { return []string{"alias", "keystore"} }
func (jdkAliases) Doc() string {
	return "trusted certificate aliases in the default JDK cacerts keystore (keytool -list -cacerts)"
}
func (jdkAliases) Platforms() []string { return nil }
func (jdkAliases) Slow() bool          { return false }

func (jdkAliases) Collect(_ table.Options) ([]table.Row, error) {
	out, ok := table.Sh("keytool", "-list", "-cacerts", "-storepass", "changeit")
	if !ok {
		return nil, nil
	}
	var rows []table.Row
	for l := range strings.SplitSeq(out, "\n") {
		if i := strings.Index(l, ","); i > 0 && strings.Contains(l, "trustedCertEntry") {
			rows = append(rows, table.Row{"alias": strings.TrimSpace(l[:i]), "keystore": "cacerts"})
		}
	}
	return rows, nil
}

func init() { table.Register(jdkAliases{}) }
