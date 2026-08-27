package keyservice

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/net/context"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKmsKeyToMasterKey(t *testing.T) {

	cases := []struct {
		description        string
		expectedArn        string
		expectedRole       string
		expectedCtx        map[string]string
		expectedAwsProfile string
	}{
		{
			description:        "empty context",
			expectedArn:        "arn:aws:kms:eu-west-1:123456789012:key/d5c90a06-f824-4628-922b-12424571ed4d",
			expectedRole:       "ExampleRole",
			expectedCtx:        map[string]string{},
			expectedAwsProfile: "",
		},
		{
			description:  "context with one key-value pair",
			expectedArn:  "arn:aws:kms:eu-west-1:123456789012:key/d5c90a06-f824-4628-922b-12424571ed4d",
			expectedRole: "",
			expectedCtx: map[string]string{
				"firstKey": "first value",
			},
			expectedAwsProfile: "ExampleProfile",
		},
		{
			description:  "context with three key-value pairs",
			expectedArn:  "arn:aws:kms:eu-west-1:123456789012:key/d5c90a06-f824-4628-922b-12424571ed4d",
			expectedRole: "",
			expectedCtx: map[string]string{
				"firstKey":  "first value",
				"secondKey": "second value",
				"thirdKey":  "third value",
			},
			expectedAwsProfile: "",
		},
	}

	for _, c := range cases {

		t.Run(c.description, func(t *testing.T) {

			inputCtx := make(map[string]string)
			for k, v := range c.expectedCtx {
				inputCtx[k] = v
			}

			key := &KmsKey{
				Arn:        c.expectedArn,
				Role:       c.expectedRole,
				Context:    inputCtx,
				AwsProfile: c.expectedAwsProfile,
			}

			masterKey := kmsKeyToMasterKey(key)
			foundCtx := masterKey.EncryptionContext

			for k := range c.expectedCtx {
				require.Containsf(t, foundCtx, k, "Context does not contain expected key '%s'", k)
			}
			for k := range foundCtx {
				require.Containsf(t, c.expectedCtx, k, "Context contains an unexpected key '%s' which cannot be found from expected map", k)
			}
			for k, expected := range c.expectedCtx {
				foundVal := *foundCtx[k]
				assert.Equalf(t, expected, foundVal, "Context key '%s' value '%s' does not match expected value '%s'", k, foundVal, expected)
			}
			assert.Equalf(t, c.expectedArn, masterKey.Arn, "Expected ARN to be '%s', but found '%s'", c.expectedArn, masterKey.Arn)
			assert.Equalf(t, c.expectedRole, masterKey.Role, "Expected Role to be '%s', but found '%s'", c.expectedRole, masterKey.Role)
			assert.Equalf(t, c.expectedAwsProfile, masterKey.AwsProfile, "Expected AWS profile to be '%s', but found '%s'", c.expectedAwsProfile, masterKey.AwsProfile)
		})
	}
}

// plugin package test helpers are unexported; keyservice needs its own copy
var (
	keyserviceTestPluginOnce sync.Once
	keyserviceTestPluginPath string
	keyserviceTestPluginErr  error
)

func buildTestPlugin(t *testing.T) string {
	t.Helper()
	keyserviceTestPluginOnce.Do(func() {
		// no cleanup: the binary must outlive every test in the package run
		dir, err := os.MkdirTemp("", "sops-keyservice-testplugin")
		if err != nil {
			keyserviceTestPluginErr = err
			return
		}
		bin := filepath.Join(dir, "sops-plugin-testplugin")
		if runtime.GOOS == "windows" {
			bin += ".exe" // plugin resolution accepts .exe only on windows
		}
		cmd := exec.Command("go", "build", "-o", bin, "../internal/testplugin")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			keyserviceTestPluginErr = fmt.Errorf("%v (go build -o %s ../internal/testplugin)", err, bin)
			return
		}
		keyserviceTestPluginPath = bin
	})
	if keyserviceTestPluginErr != nil {
		t.Fatalf("building testplugin: %v", keyserviceTestPluginErr)
	}
	return keyserviceTestPluginPath
}

func TestPluginKeyGatedByDefault(t *testing.T) {
	srv := NewServer(false)
	k := &Key{KeyType: &Key_PluginKey{PluginKey: &PluginKey{BinaryName: "testplugin", Config: `{}`}}}
	_, err := srv.Encrypt(context.Background(), &EncryptRequest{Key: k, Plaintext: []byte("dk")})
	if !errors.Is(err, errPluginsDisabled) {
		t.Fatalf("want errPluginsDisabled by default, got %v", err)
	}
}

func TestPluginKeyEncryptionWhenEnabled(t *testing.T) {
	bin := buildTestPlugin(t)
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SOPS_TESTPLUGIN_MODE", "")
	cfgPath := filepath.Join(t.TempDir(), "local.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("plugins:\n  allowed:\n    - testplugin\n"), 0o600))
	t.Setenv("SOPS_LOCAL_CONFIG", cfgPath)

	srv := NewServerWithOptions(false, true)
	k := &Key{KeyType: &Key_PluginKey{PluginKey: &PluginKey{BinaryName: "testplugin", Config: `{}`}}}
	resp, err := srv.Encrypt(context.Background(), &EncryptRequest{Key: k, Plaintext: []byte("datakey-0000000000000000")})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestPluginKeyDecryptWhenEnabled(t *testing.T) {
	bin := buildTestPlugin(t)
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SOPS_TESTPLUGIN_MODE", "")
	cfgPath := filepath.Join(t.TempDir(), "local.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("plugins:\n  allowed:\n    - testplugin\n"), 0o600))
	t.Setenv("SOPS_LOCAL_CONFIG", cfgPath)

	srv := NewServerWithOptions(false, true)
	pk := &PluginKey{BinaryName: "testplugin", Config: `{}`}
	k := &Key{KeyType: &Key_PluginKey{PluginKey: pk}}
	resp, err := srv.Encrypt(context.Background(), &EncryptRequest{Key: k, Plaintext: []byte("datakey-0000000000000000")})
	require.NoError(t, err)

	pk.Wrapped = string(resp.Ciphertext)
	dresp, err := srv.Decrypt(context.Background(), &DecryptRequest{Key: k})
	require.NoError(t, err)
	assert.Equal(t, []byte("datakey-0000000000000000"), dresp.Plaintext)
}

func TestPluginKeyBadConfigRejected(t *testing.T) {
	srv := NewServerWithOptions(false, true)
	k := &Key{KeyType: &Key_PluginKey{PluginKey: &PluginKey{BinaryName: "testplugin", Config: `not json`}}}
	_, err := srv.Encrypt(context.Background(), &EncryptRequest{Key: k, Plaintext: []byte("dk")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid plugin config")
}
