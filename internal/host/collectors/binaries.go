package collectors

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pjstein/fumigator/internal/host/table"
)

// embeddedRoots: executables that have a root store compiled in (Rust binaries built with
// rustls + webpki-roots, Go binaries that bundle a PEM, anything with a static trust store).
// The subject names in DER certificates are plain ASCII, so a byte search for the compromised
// root names finds them. Such a binary keeps trusting the chain until it is rebuilt against a
// fixed webpki-roots, whatever the OS store says.
type embeddedRoots struct{}

func (embeddedRoots) Name() string { return "binaries_embedding_roots" }
func (embeddedRoots) Columns() []string {
	return []string{"path", "name", "manager", "crate", "bad_roots"}
}
func (embeddedRoots) Doc() string {
	return "executables in ~/.cargo/bin, ~/.local/bin, ~/go/bin, Homebrew, bun, pixi, docker and podman bin dirs whose bytes contain a compromised root name (compiled-in trust store); crate = the cargo crate that installed it when known"
}
func (embeddedRoots) Platforms() []string { return nil }
func (embeddedRoots) Slow() bool          { return true }

func (embeddedRoots) Collect(opt table.Options) ([]table.Row, error) {
	home := table.Home()
	dirs := []string{
		filepath.Join(home, ".cargo", "bin"), filepath.Join(home, ".local", "bin"), filepath.Join(home, "go", "bin"),
		"/opt/homebrew/bin", "/usr/local/bin", filepath.Join(home, ".bun", "bin"), filepath.Join(home, ".pixi", "bin"),
		filepath.Join(home, ".docker", "bin"), "/opt/podman/bin",
	}
	crates := cargoCrates()
	var rows []table.Row
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	seen := map[string]bool{}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			p := filepath.Join(d, e.Name())
			real, err := filepath.EvalSymlinks(p)
			if err != nil || !table.IsExec(real) || seen[real] {
				continue
			}
			seen[real] = true
			wg.Add(1)
			sem <- struct{}{}
			go func(p, real string) {
				defer wg.Done()
				defer func() { <-sem }()
				b, err := os.ReadFile(real)
				if err != nil || !isNativeBinary(b) {
					return
				}
				hits := table.ContainsAny(b, opt.BadRoots)
				if len(hits) == 0 {
					return
				}
				mu.Lock()
				rows = append(rows, table.Row{"path": p, "name": filepath.Base(p), "manager": table.Manager(real),
					"crate": crates[filepath.Base(p)], "bad_roots": strings.Join(hits, ";")})
				mu.Unlock()
			}(p, real)
		}
	}
	wg.Wait()
	return rows, nil
}

// isNativeBinary recognises Mach-O (incl. fat) and ELF headers.
func isNativeBinary(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch {
	case b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F':
		return true
	case b[0] == 0xcf && b[1] == 0xfa && b[2] == 0xed && b[3] == 0xfe, // MH_MAGIC_64
		b[0] == 0xfe && b[1] == 0xed && b[2] == 0xfa && b[3] == 0xcf,
		b[0] == 0xca && b[1] == 0xfe && b[2] == 0xba && b[3] == 0xbe: // FAT
		return true
	}
	return false
}

// cargoCrates maps installed binary names to the crate that provides them (~/.cargo/.crates.toml).
func cargoCrates() map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(table.Home(), ".cargo", ".crates.toml"))
	if err != nil {
		return out
	}
	// lines look like: "cargo-binstall 1.10.0 (registry+https://...)" = ["cargo-binstall"]
	for l := range strings.SplitSeq(string(b), "\n") {
		if !strings.Contains(l, "= [") {
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		crate := strings.Fields(strings.Trim(strings.TrimSpace(k), `"`))
		if len(crate) == 0 {
			continue
		}
		for bin := range strings.SplitSeq(strings.Trim(strings.TrimSpace(v), "[]"), ",") {
			if bin = strings.Trim(strings.TrimSpace(bin), `"`); bin != "" {
				out[bin] = crate[0]
			}
		}
	}
	return out
}

func init() { table.Register(embeddedRoots{}) }
