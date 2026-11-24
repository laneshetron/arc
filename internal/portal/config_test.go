package portal

import "testing"

func TestParseCheckMode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want CheckMode
		ok   bool
	}{
		{"auto", CheckAuto, true},
		{"", CheckAuto, true},
		{"off", CheckOff, true},
		{"force", CheckForce, true},
		{"ON", 0, false},
		{"yes", 0, false},
	} {
		got, err := ParseCheckMode(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("ParseCheckMode(%q) err = %v, want ok=%v", tc.in, err, tc.ok)
		}
		if tc.ok && got != tc.want {
			t.Errorf("ParseCheckMode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestCheckModeEnabled covers §8's policy: off never probes, force always
// does, auto only when a tunnel is being installed.
func TestCheckModeEnabled(t *testing.T) {
	for _, tc := range []struct {
		m      CheckMode
		tunnel bool
		want   bool
	}{
		{CheckOff, true, false},
		{CheckOff, false, false},
		{CheckForce, true, true},
		{CheckForce, false, true},
		{CheckAuto, true, true},
		{CheckAuto, false, false},
	} {
		if got := tc.m.Enabled(tc.tunnel); got != tc.want {
			t.Errorf("%v.Enabled(tunnel=%v) = %v, want %v", tc.m, tc.tunnel, got, tc.want)
		}
	}
}

func TestParseExpectation(t *testing.T) {
	for _, tc := range []struct {
		in     string
		status int
		substr string
		ok     bool
	}{
		{"204", 204, "", true},
		{"200:Microsoft Connect Test", 200, "Microsoft Connect Test", true},
		{"301:/login", 301, "/login", true},
		{"", 0, "", false},
		{"abc", 0, "", false},
		{"99", 0, "", false},
		{"600", 0, "", false},
		{"200:", 0, "", false},
	} {
		got, err := ParseExpectation(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("ParseExpectation(%q) err = %v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if !tc.ok {
			continue
		}
		if got.Status != tc.status || got.Substr != tc.substr {
			t.Errorf("ParseExpectation(%q) = %+v, want %d/%q", tc.in, got, tc.status, tc.substr)
		}
	}
}

// TestConfigValidate covers §8's flag-pairing rules, which exist so a custom
// probe can never run with a guessed success criterion.
func TestConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Config
		ok   bool
	}{
		{"defaults", Config{Mode: CheckAuto}, true},
		{"probe with expectation", Config{ProbeURL: "http://a/", Expect: Expectation{Status: 204}}, true},
		{"probe without expectation", Config{ProbeURL: "http://a/"}, false},
		{"expectation without probe", Config{Expect: Expectation{Status: 204}}, false},
		{"negative duration", Config{Steady: -1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.c.Validate(); (err == nil) != tc.ok {
				t.Errorf("Validate() = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}
