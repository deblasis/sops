package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

var pinRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// gateExecution is the single choke point: every spawn must pass it. Entries
// are binary names for PATH resolution or absolute paths for path overrides.
// When an override is in play the allowlist must match the resolved absolute
// path exactly, so a name entry can never authorize whatever absolute path
// repo content picks.
func gateExecution(binaryName, resolvedPath, pathOverride string) error {
	cfg, err := loadLocalConfig()
	if err != nil {
		return fmt.Errorf("loading local plugin config: %w", err)
	}
	// a typo in the global timeout must fail loudly, never silently fall back
	// to the default and hide the misconfiguration
	if cfg.Plugins.Timeout != "" {
		if d, err := time.ParseDuration(cfg.Plugins.Timeout); err != nil {
			return fmt.Errorf("invalid plugins.timeout %q in %s: %w", cfg.Plugins.Timeout, localConfigHint(), err)
		} else if d <= 0 {
			return fmt.Errorf("invalid plugins.timeout %q in %s: must be positive", cfg.Plugins.Timeout, localConfigHint())
		}
	}
	if len(cfg.Plugins.Allowed) == 0 {
		suggestion := binaryName
		if pathOverride != "" {
			suggestion = resolvedPath
		}
		return fmt.Errorf("plugin %q blocked: no plugins.allowed list in local config (%s)\n"+
			"create that file with:\n  plugins:\n    allowed:\n      - %s\n"+
			"(only the local file grants execution; the repo .sops.yaml cannot)", binaryName, localConfigHint(), suggestion)
	}
	matched := ""
	for _, a := range cfg.Plugins.Allowed {
		if pathOverride != "" {
			if a == resolvedPath {
				matched = a
				break
			}
		} else if a == binaryName {
			matched = a
			break
		}
	}
	if matched == "" {
		if pathOverride != "" {
			return fmt.Errorf("plugin %q blocked: path override resolved to %s, which is not on the local plugins.allowed list "+
				"(path overrides must be allowlisted by absolute path; repo content cannot grant execution)", binaryName, resolvedPath)
		}
		return fmt.Errorf("plugin %q blocked: not on the local plugins.allowed list (repo content cannot grant execution)", binaryName)
	}
	// opt-in integrity: a pin tightens "a binary of this name exists" to "the
	// exact bytes the user pinned". A pin never grants execution on its own.
	if want, ok := cfg.Plugins.Pinned[matched]; ok {
		if err := checkPin(resolvedPath, want); err != nil {
			return fmt.Errorf("plugin %q blocked: %w", binaryName, err)
		}
	}
	return nil
}

// checkPin hashes the resolved binary and compares against the pinned sha256
func checkPin(resolvedPath, want string) error {
	want = strings.ToLower(strings.TrimSpace(want))
	if !pinRe.MatchString(want) {
		return fmt.Errorf("plugins.pinned entry for %s is not a sha256 digest (64 hex chars): %q", resolvedPath, want)
	}
	b, err := os.ReadFile(resolvedPath)
	if err != nil {
		return fmt.Errorf("reading %s for integrity check: %w", resolvedPath, err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("integrity check failed: %s hashes to %s but plugins.pinned pins %s "+
			"(the binary on PATH is not the one you allowlisted)", resolvedPath, got, want)
	}
	return nil
}

func localConfigHint() string {
	p, err := localConfigPath()
	if err != nil {
		return "$HOME/.sops.yaml"
	}
	return p
}

func globalTimeout() (time.Duration, bool) {
	cfg, err := loadLocalConfig()
	if err != nil || cfg.Plugins.Timeout == "" {
		return 0, false
	}
	d, err := time.ParseDuration(cfg.Plugins.Timeout)
	if err != nil {
		return 0, false
	}
	return d, true
}
