package plugin

import (
	"context"
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

	writeLocalConfig(t, "plugins:\n  allowed:\n    - testplugin\n")
	k := NewMasterKey("testplugin", nil, 0, "")
	require.NoError(t, k.Encrypt([]byte("datakey-0000000000000000")))

	writeLocalConfig(t, "plugins:\n  allowed:\n    - otherplugin\n")
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

	err = gateExecution("testplugin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading local plugin config")
}
