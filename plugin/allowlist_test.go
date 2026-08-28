package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeLocalConfig(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "local.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	t.Setenv("SOPS_LOCAL_CONFIG", path)
}

func TestAllowlistGate(t *testing.T) {
	bin := buildTestPlugin(t)
	prependPath(t, filepath.Dir(bin))
	t.Setenv("SOPS_TESTPLUGIN_MODE", "")
	resetHostRegistry()
	t.Cleanup(resetHostRegistry)

	writeLocalConfig(t, "plugins:\n  allowed:\n    - testplugin\n")
	k := NewMasterKey("testplugin", nil, 0, "")
	require.NoError(t, k.Encrypt([]byte("datakey-0000000000000000")))

	writeLocalConfig(t, "plugins:\n  allowed:\n    - otherplugin\n")
	// the gate runs at spawn: drop the allowlisted host so the next operation
	// has to spawn and hit the narrowed list
	resetHostRegistry()
	k2 := NewMasterKey("testplugin", nil, 0, "")
	err := k2.Encrypt([]byte("datakey-0000000000000000"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "testplugin")
	assert.Contains(t, err.Error(), "not on the local plugins.allowed list")
}

func TestNoAllowlistBlocksByDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SOPS_LOCAL_CONFIG", "")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	// the binary resolves (the gate runs after resolution); only the gate blocks
	prependPath(t, filepath.Dir(buildTestPlugin(t)))
	// a host cached by an earlier test already passed its gate: start bare
	resetHostRegistry()
	t.Cleanup(resetHostRegistry)

	k := NewMasterKey("testplugin", nil, 0, "")
	err := k.Encrypt([]byte("datakey-0000000000000000"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no plugins.allowed list")
	assert.Contains(t, err.Error(), filepath.Join(home, ".sops.yaml"))
}

func TestGlobalTimeoutFromLocalConfig(t *testing.T) {
	writeLocalConfig(t, "plugins:\n  timeout: 5s\n")
	cfg, err := loadLocalConfig()
	require.NoError(t, err)
	assert.Equal(t, "5s", cfg.Plugins.Timeout)

	d, ok := globalTimeout()
	require.True(t, ok)
	assert.Equal(t, "5s", d.String())
}

func TestGateBypassForConformance(t *testing.T) {
	bin := buildTestPlugin(t)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "")
	t.Setenv("SOPS_LOCAL_CONFIG", "")

	h := newHost("testplugin", bin, 2*time.Second)
	h.skipGate = true
	t.Cleanup(func() { h.kill() })
	require.NoError(t, h.start(context.Background()))

	resp, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: []byte("k")})
	require.NoError(t, err)
	require.True(t, resp.OK)
}

func TestBadLocalConfigErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.yaml")
	require.NoError(t, os.WriteFile(path, []byte("plugins: [unclosed"), 0o600))
	t.Setenv("SOPS_LOCAL_CONFIG", path)

	_, err := loadLocalConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing")

	err = gateExecution("testplugin", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading local plugin config")
}

// a path override is only executable when the allowlist names the resolved
// absolute path; a bare name entry authorizes PATH resolution, never a
// repo-chosen absolute path
func TestOverrideAllowlistRequiresExactPath(t *testing.T) {
	bin := buildTestPlugin(t)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "")

	writeLocalConfig(t, "plugins:\n  allowed:\n    - testplugin\n")
	k := NewMasterKey("testplugin", nil, 0, bin)
	err := k.Encrypt([]byte("datakey-0000000000000000"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be allowlisted by absolute path")
	assert.Contains(t, err.Error(), bin)

	writeLocalConfig(t, fmt.Sprintf("plugins:\n  allowed:\n    - %s\n", bin))
	k2 := NewMasterKey("testplugin", nil, 0, bin)
	require.NoError(t, k2.Encrypt([]byte("datakey-0000000000000000")))
}
