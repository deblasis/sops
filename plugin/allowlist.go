package plugin

import (
	"fmt"
	"time"
)

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
	if len(cfg.Plugins.Allowed) == 0 {
		suggestion := binaryName
		if pathOverride != "" {
			suggestion = resolvedPath
		}
		return fmt.Errorf("plugin %q blocked: no plugins.allowed list in local config (%s)\n"+
			"create that file with:\n  plugins:\n    allowed:\n      - %s\n"+
			"(only the local file grants execution; the repo .sops.yaml cannot)", binaryName, localConfigHint(), suggestion)
	}
	for _, a := range cfg.Plugins.Allowed {
		if pathOverride != "" {
			if a == resolvedPath {
				return nil
			}
		} else if a == binaryName {
			return nil
		}
	}
	if pathOverride != "" {
		return fmt.Errorf("plugin %q blocked: path override resolved to %s, which is not on the local plugins.allowed list "+
			"(path overrides must be allowlisted by absolute path; repo content cannot grant execution)", binaryName, resolvedPath)
	}
	return fmt.Errorf("plugin %q blocked: not on the local plugins.allowed list (repo content cannot grant execution)", binaryName)
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
