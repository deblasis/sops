package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

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

	h := newHost("testplugin", bin)
	h.skipGate = true
	t.Cleanup(func() { h.kill() })
	require.NoError(t, h.start(context.Background(), testTimeout))

	resp, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: []byte("k")})
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

func hashFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// opt-in integrity: a pin tightens an allowlist entry to the exact bytes the
// user hashed. Right pin passes, wrong pin or malformed pin blocks, no pin is
// unaffected, and a pin never grants execution by itself.
func TestPinnedAllowlistEntryChecksDigest(t *testing.T) {
	bin := buildTestPlugin(t)
	prependPath(t, filepath.Dir(bin))
	t.Setenv("SOPS_TESTPLUGIN_MODE", "")
	resetHostRegistry()
	t.Cleanup(resetHostRegistry)
	good := hashFile(t, bin)

	writeLocalConfig(t, fmt.Sprintf("plugins:\n  allowed:\n    - testplugin\n  pinned:\n    testplugin: %s\n", good))
	k := NewMasterKey("testplugin", nil, 0, "")
	require.NoError(t, k.Encrypt([]byte("datakey-0000000000000000")))

	// same allowlist entry, wrong bytes pinned: fail closed
	resetHostRegistry()
	writeLocalConfig(t, "plugins:\n  allowed:\n    - testplugin\n  pinned:\n    testplugin: 0000000000000000000000000000000000000000000000000000000000000000\n")
	k2 := NewMasterKey("testplugin", nil, 0, "")
	err := k2.Encrypt([]byte("datakey-0000000000000000"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "integrity check failed")

	// malformed pin value: fail closed, never skip
	resetHostRegistry()
	writeLocalConfig(t, "plugins:\n  allowed:\n    - testplugin\n  pinned:\n    testplugin: not-a-digest\n")
	k3 := NewMasterKey("testplugin", nil, 0, "")
	err = k3.Encrypt([]byte("datakey-0000000000000000"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a sha256 digest")

	// a pin for a binary that is not allowlisted grants nothing
	resetHostRegistry()
	writeLocalConfig(t, "plugins:\n  pinned:\n    otherplugin: "+good+"\n")
	k4 := NewMasterKey("otherplugin", nil, 0, "")
	err = k4.Encrypt([]byte("datakey-0000000000000000"))
	require.Error(t, err)
}

// a bad global timeout is a config error, not a silent fallback to 30s
func TestInvalidGlobalTimeoutFailsLoudly(t *testing.T) {
	writeLocalConfig(t, "plugins:\n  timeout: 60 sec\n")
	err := gateExecution("testplugin", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid plugins.timeout")
	assert.Contains(t, err.Error(), "60 sec")

	writeLocalConfig(t, "plugins:\n  timeout: -5s\n")
	err = gateExecution("testplugin", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be positive")
}
