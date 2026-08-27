package plugin

import (
	"fmt"
	"time"
)

// gateExecution is the single choke point: every spawn must pass it.
func gateExecution(binaryName string) error {
	cfg, err := loadLocalConfig()
	if err != nil {
		return fmt.Errorf("loading local plugin config: %w", err)
	}
	if len(cfg.Plugins.Allowed) == 0 {
		return fmt.Errorf("plugin %q blocked: no plugins.allowed list in local config (%s)\n"+
			"create that file with:\n  plugins:\n    allowed:\n      - %s\n"+
			"(only the local file grants execution; the repo .sops.yaml cannot)", binaryName, localConfigHint(), binaryName)
	}
	for _, a := range cfg.Plugins.Allowed {
		if a == binaryName {
			return nil
		}
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
