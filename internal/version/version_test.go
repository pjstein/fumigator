package version

import "testing"

func TestLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"8.3.30", "8.3.36", true},
		{"8.3.36", "8.3.36", false},
		{"v22.1.0", "22.23.4", true},
		{"22", "22.23.4", true},
		{"22.23.4", "22", false},
		{"8.3.30-fpm-alpine", "8.3.36", true},
		{">=2026.10.19", "2026.10.19", false},
		{"garbage", "1.0", false},
		{"1.27.3", "1.26.10", false},
	}
	for _, c := range cases {
		if got := Less(c.a, c.b); got != c.want {
			t.Errorf("Less(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestLine(t *testing.T) {
	if Line("8.3.30-fpm", 2) != "8.3" {
		t.Error("Line 2")
	}
	if Line("22-alpine", 1) != "22" {
		t.Error("Line 1")
	}
	if Line("22", 2) != "" {
		t.Error("Line short")
	}
	if Parts("1.26") != 2 {
		t.Error("Parts")
	}
}
