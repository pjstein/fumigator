package collectors

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pjstein/fumigator/internal/host/table"
)

// caBundles: every trust-store file a client on this machine might read, and which of the
// pack's bad root names it still lists. owner says who ships the file, which decides the fix:
//
//	apple, brew, distro, nix        the OS or package manager bundle
//	certifi:<interpreter kind>      a Python certifi package (fixed by the python_installs checks)
//	pip-vendor                      pip's private certifi copy (fixed by upgrading pip)
//	gcloud, aws-cli                 SDK-bundled bundles; gcloud:unused when custom_ca_certs_file
//	                                points elsewhere, gcloud:custom for that file
//	app:<name>                      a file inside an .app bundle (fixed by updating the app)
//	conda:<env>                     a conda environment's ssl/ bundle
type caBundles struct{}

func (caBundles) Name() string      { return "ca_bundles" }
func (caBundles) Columns() []string { return []string{"path", "owner", "bad_roots"} }
func (caBundles) Doc() string {
	return "CA bundle files (system, Homebrew, nix, certifi, pip, gcloud, AWS CLI, conda envs, .app bundles) and which compromised root names each still contains"
}
func (caBundles) Platforms() []string { return nil }
func (caBundles) Slow() bool          { return true }

var bundleNames = map[string]bool{"cacert.pem": true, "ca-bundle.crt": true, "ca-certificates.crt": true, "cert.pem": true}

func (caBundles) Collect(opt table.Options) ([]table.Row, error) {
	home := table.Home()
	cands := map[string]string{
		"/etc/ssl/cert.pem":                                         "apple",
		"/opt/homebrew/etc/ca-certificates/cert.pem":                "brew",
		"/usr/local/etc/ca-certificates/cert.pem":                   "brew",
		"/etc/ssl/certs/ca-certificates.crt":                        "distro",
		"/nix/var/nix/profiles/default/etc/ssl/certs/ca-bundle.crt": "nix",
		"/usr/local/aws-cli/awscli/botocore/cacert.pem":             "aws-cli",
	}
	// nix: ssl-cert-file in nix.conf overrides the profile's cacert for the daemon and CLI
	if b, err := os.ReadFile("/etc/nix/nix.conf"); err == nil {
		for l := range strings.SplitSeq(string(b), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok && strings.TrimSpace(k) == "ssl-cert-file" {
				if f := strings.TrimSpace(v); table.Exists(f) {
					cands["/nix/var/nix/profiles/default/etc/ssl/certs/ca-bundle.crt"] = "nix:unused"
					cands[f] = "nix:custom"
				}
			}
		}
	}
	if out, ok := table.Sh("python3", "-c", "import certifi; print(certifi.where())"); ok {
		cands[out] = "certifi:python3"
	}
	if root, ok := table.Sh("gcloud", "info", "--format=value(installation.sdk_root)"); ok && root != "" {
		// with core/custom_ca_certs_file set, gcloud reads that file instead of its bundles
		owner := "gcloud"
		// gcloud prints "Your active configuration is: [x]" on stderr before the value
		custom, ok := table.Sh("gcloud", "config", "get", "core/custom_ca_certs_file")
		if lines := strings.Split(custom, "\n"); ok && len(lines) > 0 {
			custom = strings.TrimSpace(lines[len(lines)-1])
		}
		if ok && custom != "" && custom != "(unset)" && table.Exists(custom) {
			owner = "gcloud:unused"
			cands[custom] = "gcloud:custom"
		}
		for _, rel := range []string{"lib/third_party/certifi/cacert.pem", "lib/third_party/botocore/cacert.pem", "platform/bq/third_party/certifi/cacert.pem", "platform/gsutil/third_party/certifi/certifi/cacert.pem"} {
			cands[filepath.Join(root, rel)] = owner
		}
	}
	// bundles inside .app packages and conda envs: walk, depth-limited, skipping caches and tests
	walk := func(root, owner string, maxDepth int) {
		if !table.Exists(root) {
			return
		}
		base := strings.Count(root, "/")
		// the callback never returns an error, so WalkDir cannot either
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // an unreadable entry is skipped, not fatal
			}
			if d.IsDir() {
				n := d.Name()
				if strings.Count(p, "/")-base > maxDepth || n == "pkgs" || n == "node_modules" || n == "test" || n == "tests" || n == "testdata" || n == "_vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if bundleNames[d.Name()] {
				o := owner
				switch owner {
				case "app":
					if i := strings.Index(p, ".app/"); i > 0 {
						o = "app:" + strings.TrimSuffix(filepath.Base(p[:i+4]), ".app")
					}
				case "conda":
					rel, _ := filepath.Rel(root, p)
					env := "base"
					if strings.HasPrefix(rel, "envs/") {
						env = strings.Split(rel, "/")[1]
					}
					o = "conda:" + env
				}
				cands[p] = o
			}
			return nil
		})
	}
	walk("/Applications", "app", 7)
	walk(filepath.Join(home, "Applications"), "app", 7)
	for _, base := range []string{"miniconda3", "anaconda3", "miniforge3", "mambaforge"} {
		walk(filepath.Join(home, base), "conda", 7)
	}
	var rows []table.Row
	for p, owner := range cands {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rows = append(rows, table.Row{"path": p, "owner": owner, "bad_roots": strings.Join(table.ContainsAny(b, opt.BadRoots), ";")})
	}
	return rows, nil
}

func init() { table.Register(caBundles{}) }
