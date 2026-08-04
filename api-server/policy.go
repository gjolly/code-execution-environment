// Egress policy: two layers that differ in kind.
//
//	CEILING  — networks.<egress-net>.allow in tinfoil-config.yml, enforced by
//	           nftables over *resolved IPv4 addresses* (cvmimage cmd/egress
//	           refreshes the set from DNS every 60s). Coarse: anything sharing
//	           a CDN address with an allowed host is reachable at L3. Covered
//	           by the launch measurement, so it cannot change at runtime.
//
//	SESSION  — supplied per session by the orchestrator, enforced here at L7
//	           over scheme/host/path. Fine-grained but not in the measurement,
//	           so it reaches the hardware report through the checkpoint's
//	           policy hash instead.
//
// The effective policy is their intersection. A session asking for a host
// outside the ceiling produces a visible policy.reject rather than a silent
// widening — so a compromised orchestrator cannot widen egress past what the
// release measurement already permits.
//
// The ceiling arrives as the EGRESS_CEILING env var rather than by parsing
// /tinfoil/config.yml, to avoid taking a YAML dependency into the container
// that holds the enclave TLS key. Env values written in `VAR: value` map form
// are hardcoded into tinfoil-config.yml and therefore attested — the same
// measured bytes as the networks: stanza they mirror. The two lists must be
// kept in sync; they sit ten lines apart in one measured file, and drift in
// the permissive direction is caught by nftables regardless.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Policy is the session-supplied ruleset. Rules are "scheme://host/pathglob",
// or a bare host. Deny is evaluated before Allow; anything unmatched is denied.
type Policy struct {
	Allow            []string `json:"allow"`
	Deny             []string `json:"deny"`
	TunnelOnly       []string `json:"tunnel_only"`
	MaxResponseBytes int64    `json:"max_response_bytes"`
}

// EffectivePolicy is what actually gets enforced, plus the audit trail of how
// it was derived.
type EffectivePolicy struct {
	Ceiling    []string `json:"ceiling"`
	Requested  *Policy  `json:"requested"`
	Effective  *Policy  `json:"effective"`
	Rejected   []string `json:"rejected"`
	CeilingSHA string   `json:"ceiling_sha256"`
	ReqSHA     string   `json:"requested_sha256"`
	EffSHA     string   `json:"effective_sha256"`
}

// LoadCeiling reads the attested host allowlist. An empty ceiling means no
// egress is permitted at L7 — matching a `closed` network, and failing closed
// if the env var is ever missing.
func LoadCeiling() []string {
	raw := os.Getenv("EGRESS_CEILING")
	var out []string
	for _, h := range strings.Split(raw, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// Compose intersects a requested policy with the ceiling. Rules naming a host
// outside the ceiling are dropped and reported in Rejected.
func Compose(ceiling []string, requested *Policy) (*EffectivePolicy, error) {
	if requested == nil {
		requested = &Policy{Deny: []string{"**"}}
	}

	eff := &Policy{
		Deny:             append([]string(nil), requested.Deny...),
		TunnelOnly:       append([]string(nil), requested.TunnelOnly...),
		MaxResponseBytes: requested.MaxResponseBytes,
	}

	var rejected []string
	for _, rule := range requested.Allow {
		host, err := ruleHost(rule)
		if err != nil {
			rejected = append(rejected, rule)
			continue
		}
		if !withinCeiling(ceiling, host) {
			rejected = append(rejected, rule)
			continue
		}
		eff.Allow = append(eff.Allow, rule)
	}

	ceilSHA, err := hashJSON(ceiling)
	if err != nil {
		return nil, err
	}
	reqSHA, err := hashJSON(requested)
	if err != nil {
		return nil, err
	}
	effSHA, err := hashJSON(eff)
	if err != nil {
		return nil, err
	}

	return &EffectivePolicy{
		Ceiling:    ceiling,
		Requested:  requested,
		Effective:  eff,
		Rejected:   rejected,
		CeilingSHA: ceilSHA,
		ReqSHA:     reqSHA,
		EffSHA:     effSHA,
	}, nil
}

// Decide evaluates one request. It returns the matching rule so the audit
// entry records *why* the request was allowed or denied, not just the verdict.
func (e *EffectivePolicy) Decide(rawurl string) (allowed bool, tunnel bool, rule string) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return false, false, "invalid-url"
	}
	host := strings.ToLower(u.Hostname())

	for _, r := range e.Effective.Deny {
		if matchRule(r, u.Scheme, host, u.Path) {
			return false, false, "deny:" + r
		}
	}
	for _, r := range e.Effective.Allow {
		if matchRule(r, u.Scheme, host, u.Path) {
			return true, e.isTunnelOnly(host), "allow:" + r
		}
	}
	return false, false, "default-deny"
}

// AdmitHost decides a CONNECT, where only the host is known. It is deliberately
// host-granular: it admits if any allow rule could match the host, and refuses
// only if a deny rule covers the *whole* host. Interception then re-checks every
// actual request against the full URL in Decide, so path scoping is still
// enforced for intercepted (non-tunnel) hosts; tunnel-only hosts get host
// granularity and nothing more, which the audit entry states explicitly.
func (e *EffectivePolicy) AdmitHost(host string) (allowed bool, tunnel bool, rule string) {
	host = strings.ToLower(host)

	for _, r := range e.Effective.Deny {
		if hostWideRule(r, "https", host) {
			return false, false, "deny:" + r
		}
	}
	for _, r := range e.Effective.Allow {
		if ruleHostMatches(r, "https", host) {
			return true, e.isTunnelOnly(host), "allow:" + r
		}
	}
	return false, false, "default-deny"
}

func (e *EffectivePolicy) isTunnelOnly(host string) bool {
	for _, h := range e.Effective.TunnelOnly {
		if hostMatches(strings.ToLower(h), host) {
			return true
		}
	}
	return false
}

// ruleHost extracts the host from a rule, accepting both "https://host/path"
// and a bare "host".
func ruleHost(rule string) (string, error) {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return "", fmt.Errorf("empty rule")
	}
	if rule == "**" || rule == "*" {
		return rule, nil
	}
	if !strings.Contains(rule, "://") {
		if i := strings.IndexAny(rule, "/"); i >= 0 {
			return strings.ToLower(rule[:i]), nil
		}
		return strings.ToLower(rule), nil
	}
	u, err := url.Parse(rule)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("rule %q has no host", rule)
	}
	return strings.ToLower(u.Hostname()), nil
}

// withinCeiling reports whether host is covered by the attested allowlist.
// A wildcard rule host can never be within a ceiling: the ceiling is a list of
// concrete hostnames, so "**" would grant more than the measurement allows.
func withinCeiling(ceiling []string, host string) bool {
	if host == "**" || host == "*" || strings.HasPrefix(host, "*.") {
		return false
	}
	for _, c := range ceiling {
		if c == host {
			return true
		}
	}
	return false
}

// matchRule matches a rule against a request. Supported forms:
//
//	**                      everything
//	host                    any path on that host
//	*.example.com           any subdomain (not the apex)
//	https://host/prefix/**  scheme + host + path glob
//
// In path globs, * matches within one segment and ** matches across segments.
func matchRule(rule, scheme, host, path string) bool {
	ruleScheme, ruleHost, rulePath := splitRule(rule)
	if ruleScheme != "" && ruleScheme != strings.ToLower(scheme) {
		return false
	}
	if !hostMatches(ruleHost, host) {
		return false
	}
	if rulePath == "" || rulePath == "/**" {
		return true
	}
	if path == "" {
		path = "/"
	}
	return globMatch(rulePath, path)
}

// splitRule parses a rule into its scheme, host and path glob. Scheme is "" when
// the rule omits it; path is "" for a host-only rule. The bare wildcards "**"
// and "*" parse as a host of that wildcard with an empty path, which hostMatches
// treats as matching everything.
func splitRule(rule string) (scheme, host, path string) {
	rule = strings.TrimSpace(rule)
	rest := rule
	if i := strings.Index(rule, "://"); i >= 0 {
		scheme = strings.ToLower(rule[:i])
		rest = rule[i+3:]
	}
	host = rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	return scheme, strings.ToLower(host), path
}

// ruleHostMatches is matchRule minus the path glob: it reports whether the rule
// could apply to host at all. Used at CONNECT time, where no path is known.
func ruleHostMatches(rule, scheme, host string) bool {
	ruleScheme, ruleHost, _ := splitRule(rule)
	if ruleScheme != "" && ruleScheme != strings.ToLower(scheme) {
		return false
	}
	return hostMatches(ruleHost, host)
}

// hostWideRule reports whether the rule covers the entire host regardless of
// path. A deny is host-wide only if its path is "" or "/**"; a path-scoped deny
// like "**/secret/**" narrows specific paths and must not block a CONNECT.
func hostWideRule(rule, scheme, host string) bool {
	ruleScheme, ruleHost, rulePath := splitRule(rule)
	if ruleScheme != "" && ruleScheme != strings.ToLower(scheme) {
		return false
	}
	if !hostMatches(ruleHost, host) {
		return false
	}
	return rulePath == "" || rulePath == "/**"
}

func hostMatches(ruleHost, host string) bool {
	if ruleHost == "" || ruleHost == "*" || ruleHost == "**" {
		return true
	}
	if strings.HasPrefix(ruleHost, "*.") {
		return strings.HasSuffix(host, ruleHost[1:])
	}
	return ruleHost == host
}

// globMatch matches a path pattern against a path, anchored at both ends.
// ** matches any run of characters including '/'; * matches any run that does
// not cross a '/'. Patterns are a handful of characters, so the exponential
// worst case is irrelevant and clarity wins.
func globMatch(pattern, s string) bool {
	switch {
	case pattern == "":
		return s == ""

	case strings.HasPrefix(pattern, "**"):
		rest := pattern[2:]
		for i := 0; i <= len(s); i++ {
			if globMatch(rest, s[i:]) {
				return true
			}
		}
		return false

	case strings.HasPrefix(pattern, "*"):
		rest := pattern[1:]
		for i := 0; i <= len(s); i++ {
			// A single * may not consume a path separator.
			if i > 0 && s[i-1] == '/' {
				break
			}
			if globMatch(rest, s[i:]) {
				return true
			}
		}
		return false

	default:
		return s != "" && pattern[0] == s[0] && globMatch(pattern[1:], s[1:])
	}
}

func hashJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("hashing policy: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
