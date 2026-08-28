package plugin

import (
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// Local (never committed) settings. The allowlist lives here because repo
// content is untrusted for executable selection.
type LocalConfig struct {
	Plugins struct {
		Allowed []string          `yaml:"allowed"`
		Pinned  map[string]string `yaml:"pinned"`
		Timeout string            `yaml:"timeout"`
	} `yaml:"plugins"`
}

func localConfigPath() (string, error) {
	if p := os.Getenv("SOPS_LOCAL_CONFIG"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".sops.yaml"), nil
}

func loadLocalConfig() (*LocalConfig, error) {
	path, err := localConfigPath()
	if err != nil {
		return nil, err
	}
	cfg := &LocalConfig{}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cfg, nil
}
