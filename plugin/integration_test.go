package plugin_test

// End-to-end tests: real tree + store + local keyservice + real testplugin
// process. External test package because the stores import plugin, so an
// internal test file importing stores would be an import cycle.

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/plugin"
	iniStore "github.com/getsops/sops/v3/stores/ini"
	jsonStore "github.com/getsops/sops/v3/stores/json"
	yamlStore "github.com/getsops/sops/v3/stores/yaml"
)

var (
	e2ePluginOnce sync.Once
	e2ePluginPath string
	e2ePluginErr  error
)

// same contract as the plugin package's buildTestPlugin: the binary must
// outlive every test in the run, so no cleanup
func buildE2ETestPlugin(t *testing.T) string {
	t.Helper()
	e2ePluginOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sops-plugin-e2e")
		if err != nil {
			e2ePluginErr = err
			return
		}
		bin := filepath.Join(dir, "sops-plugin-testplugin")
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", bin, "../internal/testplugin")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			e2ePluginErr = fmt.Errorf("%v (go build -o %s ../internal/testplugin)", err, bin)
			return
		}
		e2ePluginPath = bin
	})
	if e2ePluginErr != nil {
		t.Fatalf("building testplugin: %v", e2ePluginErr)
	}
	return e2ePluginPath
}

// composes the standard harness: plugin on PATH, healthy mode, local config
// allowlist. Keys built after this resolve through PATH like production.
func e2eSetup(t *testing.T) {
	t.Helper()
	bin := buildE2ETestPlugin(t)
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SOPS_TESTPLUGIN_MODE", "")
	cfgPath := filepath.Join(t.TempDir(), "local.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("plugins:\n  allowed:\n    - testplugin\n"), 0o600))
	t.Setenv("SOPS_LOCAL_CONFIG", cfgPath)
}

func newE2EPluginKey(timeout time.Duration) *plugin.MasterKey {
	return plugin.NewMasterKey("testplugin", nil, timeout, "")
}

func randomDataKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func e2ePlainBranch() sops.TreeBranch {
	return sops.TreeBranch{
		{Key: "username", Value: "admin"},
		{Key: "password", Value: "hunter2"},
	}
}

// The mock age pair from age/keysource_test.go: recipient matches identity.
const (
	e2eAgeRecipient = "age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun"
	e2eAgeIdentity  = "AGE-SECRET-KEY-1G0Q5K9TV4REQ3ZSQRMTMG8NSWQGYT0T7TZ33RAZEE0GZYVZN0APSU24RK7"
)

func newE2EAgeKey(t *testing.T) *age.MasterKey {
	t.Helper()
	t.Setenv(age.SopsAgeKeyEnv, e2eAgeIdentity)
	keys, err := age.MasterKeysFromRecipients(e2eAgeRecipient)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	return keys[0]
}

// encryptE2ETree wraps the data key with every key via EncryptIfNeeded (the
// in-process path, where the plugin key learns its KeyRef), encrypts the
// values and records the MAC.
func encryptE2ETree(t *testing.T, tree *sops.Tree, dataKey []byte) {
	t.Helper()
	for _, group := range tree.Metadata.KeyGroups {
		for _, key := range group {
			require.NoError(t, key.EncryptIfNeeded(dataKey), "wrapping with %s", key.ToString())
		}
	}
	mac, err := tree.Encrypt(dataKey, aes.NewCipher())
	require.NoError(t, err)
	tree.Metadata.MessageAuthenticationCode = mac
}

func TestE2EStoreRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		store sops.Store
	}{
		{"json", &jsonStore.Store{}},
		{"yaml", &yamlStore.Store{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e2eSetup(t)
			dataKey := randomDataKey(t)
			plain := e2ePlainBranch()
			tree := sops.Tree{
				Branches: sops.TreeBranches{
					{
						{Key: "username", Value: "admin"},
						{Key: "password", Value: "hunter2"},
					},
				},
				Metadata: sops.Metadata{
					Version:   "3.10.0",
					KeyGroups: []sops.KeyGroup{{newE2EPluginKey(5 * time.Second)}},
				},
			}

			encryptE2ETree(t, &tree, dataKey)

			out, err := tc.store.EmitEncryptedFile(tree)
			require.NoError(t, err)
			assert.NotContains(t, string(out), "hunter2")

			loaded, err := tc.store.LoadEncryptedFile(out)
			require.NoError(t, err)
			require.Len(t, loaded.Metadata.KeyGroups, 1)
			require.Len(t, loaded.Metadata.KeyGroups[0], 1)
			key, ok := loaded.Metadata.KeyGroups[0][0].(*plugin.MasterKey)
			require.True(t, ok, "got %T", loaded.Metadata.KeyGroups[0][0])
			assert.Equal(t, "testplugin", key.BinaryName)
			assert.Equal(t, "testkey/primary", key.KeyRef)
			assert.NotEmpty(t, key.WrappedKey)

			gotKey, err := loaded.Metadata.GetDataKey()
			require.NoError(t, err)
			assert.Equal(t, dataKey, gotKey)

			mac, err := loaded.Decrypt(gotKey, aes.NewCipher())
			require.NoError(t, err)
			assert.Equal(t, loaded.Metadata.MessageAuthenticationCode, mac)
			assert.True(t, plain.Equals(loaded.Branches[0]),
				"decrypted branch mismatch: %v", loaded.Branches[0])
		})
	}
}

func TestE2ERotation(t *testing.T) {
	e2eSetup(t)
	dataKey := randomDataKey(t)

	// key as it sits in the file: wrapped under a key the rule no longer wants
	stale := newE2EPluginKey(5 * time.Second)
	require.NoError(t, stale.Encrypt(dataKey))
	stale.KeyRef = "testkey/old"
	stale.ExpectedKeyRef = "testkey/new" // creation rule now demands testkey/new
	require.True(t, stale.NeedsRotation())

	// updatekeys: replace the metadata key with a fresh one built from the rule
	fresh := newE2EPluginKey(5 * time.Second)
	fresh.ExpectedKeyRef = "testkey/new"
	require.NoError(t, fresh.EncryptIfNeeded(dataKey))
	// same data key, so the deterministic testplugin re-wraps to the same
	// blob; what matters is that the plugin answered with a key ref
	assert.NotEmpty(t, fresh.WrappedKey)
	assert.Equal(t, "testkey/primary", fresh.KeyRef)

	// and that spelling survives a real store round trip
	tree := sops.Tree{
		Branches: sops.TreeBranches{
			{
				{Key: "username", Value: "admin"},
				{Key: "password", Value: "hunter2"},
			},
		},
		Metadata: sops.Metadata{
			Version:   "3.10.0",
			KeyGroups: []sops.KeyGroup{{fresh}},
		},
	}
	encryptE2ETree(t, &tree, dataKey)
	out, err := (&jsonStore.Store{}).EmitEncryptedFile(tree)
	require.NoError(t, err)

	loaded, err := (&jsonStore.Store{}).LoadEncryptedFile(out)
	require.NoError(t, err)
	key, ok := loaded.Metadata.KeyGroups[0][0].(*plugin.MasterKey)
	require.True(t, ok)
	assert.Equal(t, "testkey/primary", key.KeyRef)

	gotKey, err := loaded.Metadata.GetDataKey()
	require.NoError(t, err)
	assert.Equal(t, dataKey, gotKey)
}

func TestE2EMixedGroupRescue(t *testing.T) {
	e2eSetup(t)
	dataKey := randomDataKey(t)
	plain := e2ePlainBranch()

	pk := newE2EPluginKey(5 * time.Second)
	ak := newE2EAgeKey(t)
	tree := sops.Tree{
		Branches: sops.TreeBranches{
			{
				{Key: "username", Value: "admin"},
				{Key: "password", Value: "hunter2"},
			},
		},
		Metadata: sops.Metadata{
			Version:   "3.10.0",
			KeyGroups: []sops.KeyGroup{{pk, ak}},
		},
	}
	encryptE2ETree(t, &tree, dataKey)
	assert.NotEmpty(t, pk.WrappedKey)
	assert.NotEmpty(t, ak.EncryptedKey)

	out, err := (&jsonStore.Store{}).EmitEncryptedFile(tree)
	require.NoError(t, err)
	loaded, err := (&jsonStore.Store{}).LoadEncryptedFile(out)
	require.NoError(t, err)

	// the plugin refuses at decrypt time; the age key in the same group rescues
	t.Setenv("SOPS_TESTPLUGIN_MODE", "authfail")
	gotKey, err := loaded.Metadata.GetDataKey()
	require.NoError(t, err)
	assert.Equal(t, dataKey, gotKey)

	mac, err := loaded.Decrypt(gotKey, aes.NewCipher())
	require.NoError(t, err)
	assert.Equal(t, loaded.Metadata.MessageAuthenticationCode, mac)
	assert.True(t, plain.Equals(loaded.Branches[0]),
		"decrypted branch mismatch: %v", loaded.Branches[0])
}

func TestE2ENoRuleRewrapKeepsWrappedKey(t *testing.T) {
	e2eSetup(t)
	dataKey := randomDataKey(t)

	// mode "never" hangs any spawn; a 1s timeout means a spawn costs at least a
	// second, so fast success proves EncryptIfNeeded never spawned
	k := newE2EPluginKey(1 * time.Second)
	k.SetEncryptedDataKey([]byte("prior.v1.wrap"))
	t.Setenv("SOPS_TESTPLUGIN_MODE", "never")

	start := time.Now()
	require.NoError(t, k.EncryptIfNeeded(dataKey))
	elapsed := time.Since(start)
	assert.Less(t, elapsed, 900*time.Millisecond, "EncryptIfNeeded spawned (took %v)", elapsed)
	assert.Equal(t, "prior.v1.wrap", string(k.EncryptedDataKey()))
	assert.Empty(t, k.KeyRef, "no spawn means no plugin answer")
}

func TestE2ELegacyMetadataNeutrality(t *testing.T) {
	cases := []struct {
		name  string
		store sops.Store
	}{
		{"json", &jsonStore.Store{}},
		{"yaml", &yamlStore.Store{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e2eSetup(t)
			dataKey := randomDataKey(t)
			ak := newE2EAgeKey(t)
			tree := sops.Tree{
				Branches: sops.TreeBranches{
					{
						{Key: "username", Value: "admin"},
						{Key: "password", Value: "hunter2"},
					},
				},
				Metadata: sops.Metadata{
					Version:   "3.9.4",
					KeyGroups: []sops.KeyGroup{{ak}},
				},
			}
			encryptE2ETree(t, &tree, dataKey)

			out, err := tc.store.EmitEncryptedFile(tree)
			require.NoError(t, err)

			loaded, err := tc.store.LoadEncryptedFile(out)
			require.NoError(t, err)
			require.Len(t, loaded.Metadata.KeyGroups, 1)
			require.Len(t, loaded.Metadata.KeyGroups[0], 1)
			_, isPlugin := loaded.Metadata.KeyGroups[0][0].(*plugin.MasterKey)
			assert.False(t, isPlugin, "plugin key appeared from an age-only file")

			gotKey, err := loaded.Metadata.GetDataKey()
			require.NoError(t, err)
			assert.Equal(t, dataKey, gotKey)

			// re-emit the loaded tree: still no plugin key anywhere on the wire
			reOut, err := tc.store.EmitEncryptedFile(loaded)
			require.NoError(t, err)
			assert.NotContains(t, string(reOut), "plugin")
		})
	}
}

// proves the flattened metadata spelling (sops.plugin__list_0__map_binary_name
// style keys) round-trips the plugin key array through the ini store
func TestE2EIniStore(t *testing.T) {
	e2eSetup(t)
	dataKey := randomDataKey(t)
	store := iniStore.NewStore(nil)

	tree := sops.Tree{
		Branches: sops.TreeBranches{
			{
				{Key: "database", Value: sops.TreeBranch{
					{Key: "username", Value: "admin"},
					{Key: "password", Value: "hunter2"},
				}},
			},
		},
		Metadata: sops.Metadata{
			Version:   "3.10.0",
			KeyGroups: []sops.KeyGroup{{newE2EPluginKey(5 * time.Second)}},
		},
	}
	encryptE2ETree(t, &tree, dataKey)

	out, err := store.EmitEncryptedFile(tree)
	require.NoError(t, err)
	assert.Contains(t, string(out), "plugin__list_0__map_binary_name")

	loaded, err := store.LoadEncryptedFile(out)
	require.NoError(t, err)
	require.Len(t, loaded.Metadata.KeyGroups[0], 1)
	key, ok := loaded.Metadata.KeyGroups[0][0].(*plugin.MasterKey)
	require.True(t, ok, "got %T", loaded.Metadata.KeyGroups[0][0])
	assert.Equal(t, "testplugin", key.BinaryName)
	assert.Equal(t, "testkey/primary", key.KeyRef)
	assert.NotEmpty(t, key.WrappedKey)

	gotKey, err := loaded.Metadata.GetDataKey()
	require.NoError(t, err)
	assert.Equal(t, dataKey, gotKey)

	_, err = loaded.Decrypt(gotKey, aes.NewCipher())
	require.NoError(t, err)
	// the ini loader puts a leading DEFAULT section first, so locate by key
	for _, item := range loaded.Branches[0] {
		if item.Key == "database" {
			section := item.Value.(sops.TreeBranch)
			assert.Equal(t, "admin", section[0].Value)
			assert.Equal(t, "hunter2", section[1].Value)
			return
		}
	}
	t.Fatal("database section not found after round trip")
}
