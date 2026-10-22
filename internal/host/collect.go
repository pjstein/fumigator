package host

import (
	"runtime"
	"slices"
	"sort"
	"sync"

	"github.com/pjstein/fumigator/internal/host/table"
)

// Table re-exports the collector output type for callers outside the host package.
type Table = table.Table

// Options re-exports collector options.
type Options = table.Options

// Collect runs every registered collector for this platform concurrently.
func Collect(opt Options) map[string]*Table {
	out := map[string]*Table{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range table.All() {
		if ps := c.Platforms(); ps != nil && !slices.Contains(ps, runtime.GOOS) {
			continue
		}
		if opt.Fast && c.Slow() {
			continue
		}
		wg.Add(1)
		go func(c table.Collector) {
			defer wg.Done()
			t := &Table{Name: c.Name(), Columns: c.Columns()}
			rows, err := c.Collect(opt)
			if err != nil {
				t.Err = err.Error()
			}
			t.Rows = rows
			cols := c.Columns()
			sort.SliceStable(t.Rows, func(i, j int) bool {
				for _, col := range cols {
					if t.Rows[i][col] != t.Rows[j][col] {
						return t.Rows[i][col] < t.Rows[j][col]
					}
				}
				return false
			})
			mu.Lock()
			out[c.Name()] = t
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	return out
}

// Collectors lists the registered collectors for documentation and --collectors.
func Collectors() []table.Collector { return table.All() }
