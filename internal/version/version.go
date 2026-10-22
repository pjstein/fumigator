// Package version compares dotted numeric versions the way the advisories state them:
// "8.3.30" < "8.3.36", "22" has two fewer parts than "22.23.4", leading "v" and range
// operators are stripped, and anything after the first non-numeric run is ignored
// ("8.3.30-fpm-alpine" -> 8.3.30).
package version

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	leadJunk = regexp.MustCompile(`^[vV^~>=<!\s]*`)
	numRun   = regexp.MustCompile(`^(\d+(?:\.\d+)*)`)
)

// Parse returns the numeric parts of v. ok is false when v has no leading number.
func Parse(v string) (parts []int, ok bool) {
	v = leadJunk.ReplaceAllString(strings.TrimSpace(v), "")
	m := numRun.FindString(v)
	if m == "" {
		return nil, false
	}
	for p := range strings.SplitSeq(m, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		parts = append(parts, n)
	}
	return parts, true
}

// Numeric returns the "8.3.30" prefix of a tag like "8.3.30-fpm-alpine", or "" if none.
func Numeric(v string) string {
	v = leadJunk.ReplaceAllString(strings.TrimSpace(v), "")
	return numRun.FindString(v)
}

// Less reports a < b. Missing trailing parts count as zero, so "22" == "22.0.0".
// Unparseable inputs are never less than anything.
func Less(a, b string) bool {
	pa, oka := Parse(a)
	pb, okb := Parse(b)
	if !oka || !okb {
		return false
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// Line returns the first n parts of v joined by dots: Line("8.3.30", 2) == "8.3".
// Returns "" when v has fewer than n parts or does not parse.
func Line(v string, n int) string {
	p, ok := Parse(v)
	if !ok || len(p) < n {
		return ""
	}
	s := make([]string, n)
	for i := range n {
		s[i] = strconv.Itoa(p[i])
	}
	return strings.Join(s, ".")
}

// Parts returns how many numeric parts v has (0 if unparseable).
func Parts(v string) int {
	p, ok := Parse(v)
	if !ok {
		return 0
	}
	return len(p)
}
