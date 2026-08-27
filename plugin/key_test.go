package plugin

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKey(t *testing.T, mode string) *MasterKey {
	t.Helper()
	bin := buildTestPlugin(t)
	t.Setenv("SOPS_TESTPLUGIN_MODE", mode)
	return NewMasterKey("testplugin", map[string]any{"k": "v"}, 2*time.Second, bin)
}

func TestEncryptDecryptViaKey(t *testing.T) {
	k := newTestKey(t, "")
	plain := []byte("datakey-0000000000000000")
	require.NoError(t, k.Encrypt(plain))
	assert.Equal(t, wrapForTest(string(plain)), string(k.EncryptedDataKey()))
	assert.NotEmpty(t, k.EncryptedDataKey())
	assert.Equal(t, "testkey/primary", k.KeyRef)
	assert.Equal(t, "1.2.3", k.PluginVersion)

	out, err := k.Decrypt()
	require.NoError(t, err)
	assert.Equal(t, plain, out)
}

func TestEncryptIfNeededSkipsProcess(t *testing.T) {
	k := newTestKey(t, "")
	k.SetEncryptedDataKey([]byte("already-wrapped"))
	require.NoError(t, k.EncryptIfNeeded([]byte("datakey-0000000000000000")))
	assert.Equal(t, "already-wrapped", string(k.EncryptedDataKey()))
}

func TestNeedsRotation(t *testing.T) {
	k := newTestKey(t, "")
	k.ExpectedKeyRef = "testkey/new"
	k.KeyRef = "testkey/old"
	assert.True(t, k.NeedsRotation())

	k.KeyRef = "testkey/new"
	assert.False(t, k.NeedsRotation())

	k.ExpectedKeyRef = ""
	assert.False(t, k.NeedsRotation())
}

func TestToStringIncludesIdentity(t *testing.T) {
	k := newTestKey(t, "")
	k.KeyRef = "testkey/primary"
	assert.Contains(t, k.ToString(), "testplugin")
	assert.Contains(t, k.ToString(), "testkey/primary")
}

func TestTypeToIdentifierStable(t *testing.T) {
	k := newTestKey(t, "")
	assert.Equal(t, "plugin", k.TypeToIdentifier())
}

func TestToMap(t *testing.T) {
	k := newTestKey(t, "")
	k.WrappedKey = "wrapped-1"
	k.KeyRef = "testkey/primary"
	k.PluginVersion = "1.2.3"
	m := k.ToMap()
	for _, key := range []string{"binary_name", "key_ref", "enc", "created_at", "plugin_version"} {
		assert.Contains(t, m, key)
	}
	assert.Equal(t, "testplugin", m["binary_name"])
	assert.Equal(t, "wrapped-1", m["enc"])
	assert.Equal(t, "testkey/primary", m["key_ref"])
	_, err := time.Parse(time.RFC3339, m["created_at"].(string))
	assert.NoError(t, err)
	assert.NotContains(t, m, "config")
	assert.NotContains(t, m, "timeout")
}

func TestEncryptAuthFailureSurfaces(t *testing.T) {
	k := newTestKey(t, "authfail")
	err := k.Encrypt([]byte("datakey-0000000000000000"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth_failed")
	assert.Contains(t, err.Error(), "testplugin")
	var pe *pluginError
	assert.True(t, errors.As(err, &pe), "got: %v", err)
	assert.Equal(t, errCodeAuthFailed, pe.Code)
}

func TestDecryptWithoutWrappedKeyFailsFast(t *testing.T) {
	// mode "never" hangs on any spawn; a pre-spawn guard returns instantly
	k := newTestKey(t, "never")
	start := time.Now()
	_, err := k.Decrypt()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no wrapped key to decrypt")
	assert.Less(t, time.Since(start), time.Second)
}

func TestEncryptCapturesHostVersion(t *testing.T) {
	k := newTestKey(t, "")
	require.NoError(t, k.Encrypt([]byte("datakey-0000000000000000")))
	assert.Equal(t, "1.2.3", k.PluginVersion)
}
