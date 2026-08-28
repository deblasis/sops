package plugin

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captureHook struct {
	mu      sync.Mutex
	entries []string
}

func (h *captureHook) Levels() []logrus.Level { return logrus.AllLevels }
func (h *captureHook) Fire(e *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, e.Message)
	return nil
}

func newTestKey(t *testing.T, mode string) *MasterKey {
	t.Helper()
	bin := buildTestPlugin(t)
	allowTestPlugin(t, bin)
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

// at config-parse time only ExpectedKeyRef is set; identity must not collapse
func TestToStringFallsBackToExpectedKeyRef(t *testing.T) {
	k := newTestKey(t, "")
	k.ExpectedKeyRef = "testkey/new"
	assert.Equal(t, "testplugin:testkey/new", k.ToString())
}

// no key ref at all: config digest distinguishes same-binary keys, identical configs stay equal
func TestToStringDigestsConfigWithoutKeyRef(t *testing.T) {
	k1 := NewMasterKey("testplugin", map[string]any{"a": 1}, time.Second, "")
	k2 := NewMasterKey("testplugin", map[string]any{"b": 2}, time.Second, "")
	k3 := NewMasterKey("testplugin", map[string]any{"a": 1}, time.Second, "")
	assert.Regexp(t, `^testplugin:[0-9a-f]{8}$`, k1.ToString())
	assert.NotEqual(t, k1.ToString(), k2.ToString())
	assert.Equal(t, k1.ToString(), k3.ToString())

	k4 := NewMasterKey("testplugin", nil, time.Second, "")
	assert.Equal(t, "testplugin", k4.ToString())
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

// spec section 6: an answer with a malformed error object fails the operation
// plainly; every shape below is an answer, never a respawn trigger
func TestMalformedErrorObjectsFailPlainly(t *testing.T) {
	shapeErrs := map[string]string{
		// ok:false, complete error object: surfaces as the plugin's error
		"authfail": "auth_failed",
		// ok:false, no error object at all
		"bare_false": "ok:false without an error object",
		// ok:false, error object missing its message
		"incomplete_err": "ok:false with an incomplete error object",
		// ok:true carrying an error object anyway
		"ok_with_err": "ok:true with an error object",
	}
	for mode, want := range shapeErrs {
		t.Run(mode, func(t *testing.T) {
			k := newTestKey(t, mode)
			err := k.Encrypt([]byte("datakey-0000000000000000"))
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
			assert.Contains(t, err.Error(), "encrypt")
		})
	}

	// same shapes must fail decrypt the same way
	for mode, want := range shapeErrs {
		t.Run(mode+"/decrypt", func(t *testing.T) {
			k := newTestKey(t, mode)
			k.SetEncryptedDataKey([]byte(wrapForTest("datakey-0000000000000000")))
			_, err := k.Decrypt()
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
			assert.Contains(t, err.Error(), "decrypt")
		})
	}
}

// spec section 6: a code outside the frozen list is treated as internal
func TestUnknownErrorCodeTreatedAsInternal(t *testing.T) {
	k := NewMasterKey("testplugin", nil, time.Second, "")
	err := k.answerError("encrypt", &response{OK: false, Error: &pluginError{Code: "weird_code", Message: "boom"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
	var pe *pluginError
	require.True(t, errors.As(err, &pe), "got: %v", err)
	assert.Equal(t, errCodeInternal, pe.Code)
}

// the ok:true-with-no-payload diagnoses must name the binary: without it the
// user cannot tell which plugin misbehaved
func TestEmptyAnswerDiagnosesNameBinary(t *testing.T) {
	k := newTestKey(t, "empty_ok")
	err := k.Encrypt([]byte("datakey-0000000000000000"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plugin testplugin returned no wrapped key")

	k = newTestKey(t, "empty_ok")
	k.SetEncryptedDataKey([]byte(wrapForTest("datakey-0000000000000000")))
	_, err = k.Decrypt()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plugin testplugin returned no plaintext")
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

// stderr from an otherwise-successful operation must reach the user's log,
// not only budget-exhaustion errors
func TestStderrSurfacedAtWarnAfterCompletedOps(t *testing.T) {
	hook := &captureHook{}
	logger := logrus.StandardLogger()
	prev := logger.ReplaceHooks(map[logrus.Level][]logrus.Hook{
		logrus.WarnLevel: {hook},
	})
	defer logger.ReplaceHooks(prev)

	k := newTestKey(t, "stderrnoise")
	require.NoError(t, k.Encrypt([]byte("datakey-0000000000000000")))
	_, err := k.Decrypt()
	require.NoError(t, err)

	hook.mu.Lock()
	defer hook.mu.Unlock()
	var warned []string
	for _, m := range hook.entries {
		if strings.HasPrefix(m, "plugin testplugin stderr:") {
			warned = append(warned, m)
		}
	}
	require.Len(t, warned, 2, "one warn per completed operation: %v", hook.entries)
	assert.Contains(t, warned[0], "running in fake mode")
}
