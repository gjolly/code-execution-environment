package main

import "testing"

// The load-bearing property: a session may narrow the attested ceiling but
// never widen it, and what it was refused is visible rather than silent.
func TestCompose_CeilingCannotBeWidened(t *testing.T) {
	ceiling := []string{"pypi.org", "files.pythonhosted.org"}

	eff, err := Compose(ceiling, &Policy{
		Allow: []string{
			"https://pypi.org/simple/**",  // within the ceiling
			"https://evil.example.com/**", // outside — must be refused
			"**",                          // a bid to widen everything
		},
		Deny: []string{"**"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(eff.Effective.Allow) != 1 || eff.Effective.Allow[0] != "https://pypi.org/simple/**" {
		t.Errorf("effective allow = %v, want only the in-ceiling rule", eff.Effective.Allow)
	}
	if len(eff.Rejected) != 2 {
		t.Errorf("rejected = %v, want both out-of-ceiling rules", eff.Rejected)
	}
	if eff.EffSHA == eff.ReqSHA {
		t.Error("effective and requested hashes must differ once rules were dropped")
	}
}

func TestCompose_EmptyCeilingAllowsNothing(t *testing.T) {
	eff, err := Compose(nil, &Policy{Allow: []string{"https://pypi.org/**"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(eff.Effective.Allow) != 0 {
		t.Errorf("effective allow = %v, want empty — a missing ceiling must fail closed", eff.Effective.Allow)
	}
}

func TestDecide(t *testing.T) {
	eff, err := Compose(
		[]string{"pypi.org", "api.example.com"},
		&Policy{
			Allow:      []string{"https://pypi.org/simple/**", "https://api.example.com/v1/**"},
			Deny:       []string{"https://pypi.org/simple/secret/**"},
			TunnelOnly: []string{"api.example.com"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		url        string
		wantAllow  bool
		wantTunnel bool
	}{
		{"https://pypi.org/simple/numpy/", true, false},
		{"https://pypi.org/simple/secret/x", false, false}, // deny beats allow
		{"https://pypi.org/admin", false, false},           // path outside the allow glob
		{"https://evil.example.com/", false, false},
		{"http://pypi.org/simple/numpy/", false, false}, // scheme must match
		{"https://api.example.com/v1/x", true, true},    // tunnel-only host
	}

	for _, tc := range tests {
		allow, tunnel, rule := eff.Decide(tc.url)
		if allow != tc.wantAllow {
			t.Errorf("%s: allowed = %v, want %v (rule %s)", tc.url, allow, tc.wantAllow, rule)
		}
		if allow && tunnel != tc.wantTunnel {
			t.Errorf("%s: tunnel = %v, want %v", tc.url, tunnel, tc.wantTunnel)
		}
		if rule == "" {
			t.Errorf("%s: no rule recorded — the audit entry must say why", tc.url)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"/simple/**", "/simple/numpy/", true},
		{"/simple/**", "/simple/", true},
		{"/simple/**", "/other/", false},
		{"/v1/*", "/v1/users", true},
		{"/v1/*", "/v1/users/42", false}, // * must not cross a separator
		{"/v1/**", "/v1/users/42", true},
		{"/a/*/c", "/a/b/c", true},
		{"/a/*/c", "/a/b/x/c", false},
		{"/exact", "/exact", true},
		{"/exact", "/exact/more", false}, // anchored at both ends
		{"/**/c", "/a/b/c", true},
	}

	for _, tc := range tests {
		if got := globMatch(tc.pattern, tc.path); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestHostMatches(t *testing.T) {
	tests := []struct {
		rule, host string
		want       bool
	}{
		{"pypi.org", "pypi.org", true},
		{"pypi.org", "evil.pypi.org", false},
		{"*.pypi.org", "files.pypi.org", true},
		{"*.pypi.org", "pypi.org", false}, // apex is not a subdomain
		{"*", "anything.test", true},
	}
	for _, tc := range tests {
		if got := hostMatches(tc.rule, tc.host); got != tc.want {
			t.Errorf("hostMatches(%q, %q) = %v, want %v", tc.rule, tc.host, got, tc.want)
		}
	}
}

// A wildcard can never sit inside a ceiling of concrete hostnames — otherwise
// one "**" rule would grant more than the measurement allows.
func TestWithinCeiling_RejectsWildcards(t *testing.T) {
	ceiling := []string{"pypi.org"}
	for _, host := range []string{"**", "*", "*.pypi.org"} {
		if withinCeiling(ceiling, host) {
			t.Errorf("withinCeiling(%q) = true, want false", host)
		}
	}
	if !withinCeiling(ceiling, "pypi.org") {
		t.Error("an exact ceiling host must be within the ceiling")
	}
}
