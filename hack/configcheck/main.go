// configcheck asserts the invariants tinfoil-config.yml must hold for the
// audit log to mean anything. It lives in its own module so api-server and
// executor stay dependency-free — they hold the enclave TLS key, and every
// dependency there is attack surface on it.
//
// cvmimage validates this file too, but its checks are about internal
// consistency, not about our security properties. In particular it accepts
//
//	executor:
//	  networks: ["sandbox-net", "egress-net"]
//
// without complaint — "at most one attached network may have egress != closed"
// is satisfied. That config gives the sandbox a direct route to the internet,
// bypassing the proxy entirely and making the transcript a record of only the
// traffic that happened to be polite. Nothing upstream stops it, so we do.
//
// Usage: go run ./hack/configcheck tinfoil-config.yml
package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// sandboxContainer is the untrusted one: it runs model-authored bash.
const sandboxContainer = "executor"

// recorderContainer is the one that must be the sole egress path.
const recorderContainer = "api-server"

type config struct {
	Networks   map[string]*networkSpec `yaml:"networks"`
	Containers []container             `yaml:"containers"`
	Shim       shimStanza              `yaml:"shim"`
}

type shimStanza struct {
	UpstreamContainer string   `yaml:"upstream-container"`
	Paths             []string `yaml:"paths"`
}

type networkSpec struct {
	Egress string   `yaml:"egress"`
	Allow  []string `yaml:"allow"`
}

// UnmarshalYAML mirrors cvmimage: a null body means egress: closed.
func (n *networkSpec) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		n.Egress = "closed"
		return nil
	}
	type alias networkSpec
	var raw alias
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*n = networkSpec(raw)
	if n.Egress == "" {
		n.Egress = "closed"
	}
	return nil
}

type container struct {
	Name     string   `yaml:"name"`
	User     string   `yaml:"user"`
	Networks []string `yaml:"networks"`
	Volumes  []string `yaml:"volumes"`
	Env      []any    `yaml:"env"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: configcheck <tinfoil-config.yml>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "parsing config:", err)
		os.Exit(2)
	}

	problems := check(&cfg)
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "FAIL:", p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
	fmt.Println("configcheck: all invariants hold")
}

func check(cfg *config) []string {
	var problems []string

	// `name:` with a null body leaves a nil pointer — UnmarshalYAML is not
	// called for it. cvmimage materializes these as default-closed before
	// validating (cmd/boot/network_validate.go); do the same or every null
	// network dereferences nil.
	for name, spec := range cfg.Networks {
		if spec == nil {
			cfg.Networks[name] = &networkSpec{Egress: "closed"}
		}
	}

	byName := map[string]container{}
	for _, c := range cfg.Containers {
		byName[c.Name] = c
	}

	sandbox, ok := byName[sandboxContainer]
	if !ok {
		return []string{fmt.Sprintf("no container named %q", sandboxContainer)}
	}
	recorder, ok := byName[recorderContainer]
	if !ok {
		return []string{fmt.Sprintf("no container named %q", recorderContainer)}
	}

	// THE invariant. Everything else in the design is downstream of this: if
	// the sandbox can route anywhere itself, the proxy is advisory and the
	// transcript is incomplete.
	for _, n := range sandbox.Networks {
		spec, ok := cfg.Networks[n]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s is on undeclared network %q", sandboxContainer, n))
			continue
		}
		if spec.Egress != "closed" {
			problems = append(problems, fmt.Sprintf(
				"%s is attached to %q which has egress: %s — the sandbox must have no route of its own, "+
					"or the audit log records only the traffic that chose to be recorded",
				sandboxContainer, n, spec.Egress))
		}
	}

	// The two must share a bridge, or the sandbox cannot reach the proxy and
	// has no network at all.
	if !sharesNetwork(sandbox.Networks, recorder.Networks) {
		problems = append(problems, fmt.Sprintf(
			"%s and %s share no network; the sandbox cannot reach the proxy",
			sandboxContainer, recorderContainer))
	}

	// The recorder needs exactly one way out.
	egressNets := 0
	for _, n := range recorder.Networks {
		if spec, ok := cfg.Networks[n]; ok && spec.Egress != "closed" {
			egressNets++
		}
	}
	if egressNets == 0 {
		problems = append(problems, fmt.Sprintf(
			"%s has no egress-capable network; nothing can reach the internet", recorderContainer))
	}

	// uid 0 is required to read the root-owned 0600 TLS key. If someone
	// re-adds `user:` the checkpoint signer fails at startup, which is a
	// confusing way to discover this.
	if recorder.User != "" {
		problems = append(problems, fmt.Sprintf(
			"%s sets user: %q, but uid 0 is required to read the bind-mounted TLS key",
			recorderContainer, recorder.User))
	}

	if !hasTLSMount(recorder.Volumes) {
		problems = append(problems, fmt.Sprintf(
			"%s does not mount /mnt/ramdisk/private/tls; audit checkpoints cannot be signed "+
				"and transcripts would not be attributable to this CVM", recorderContainer))
	}

	// The sandbox must never see the enclave key.
	if hasTLSMount(sandbox.Volumes) {
		problems = append(problems, fmt.Sprintf(
			"%s mounts the enclave TLS key; it is untrusted and must never see it", sandboxContainer))
	}

	// The ceiling the api-server enforces at L7 must match the one nftables
	// enforces at L3, or the two layers disagree about what is permitted.
	if egressNet := firstEgressNetwork(cfg, recorder.Networks); egressNet != "" {
		want := cfg.Networks[egressNet].Allow
		got := ceilingEnv(recorder.Env)
		if !slices.Equal(want, got) {
			problems = append(problems, fmt.Sprintf(
				"EGRESS_CEILING=%v does not match networks.%s.allow=%v; the L7 and L3 ceilings must agree",
				got, egressNet, want))
		}
	}

	if !slices.Contains(cfg.Shim.Paths, "/audit/*") {
		problems = append(problems, "shim.paths does not expose /audit/*; the transcript is unreachable")
	}
	if cfg.Shim.UpstreamContainer != "" && cfg.Shim.UpstreamContainer != recorderContainer {
		problems = append(problems, fmt.Sprintf(
			"shim.upstream-container is %q, want %q", cfg.Shim.UpstreamContainer, recorderContainer))
	}

	return problems
}

func sharesNetwork(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

func firstEgressNetwork(cfg *config, networks []string) string {
	for _, n := range networks {
		if spec, ok := cfg.Networks[n]; ok && spec.Egress != "closed" {
			return n
		}
	}
	return ""
}

func hasTLSMount(volumes []string) bool {
	for _, v := range volumes {
		if strings.HasPrefix(v, "/mnt/ramdisk/private/tls") {
			return true
		}
	}
	return false
}

// ceilingEnv pulls EGRESS_CEILING out of the `- VAR: value` map form.
func ceilingEnv(env []any) []string {
	for _, e := range env {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		v, ok := m["EGRESS_CEILING"]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		var out []string
		for _, h := range strings.Split(s, ",") {
			if h = strings.TrimSpace(h); h != "" {
				out = append(out, h)
			}
		}
		return out
	}
	return nil
}
