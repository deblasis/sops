package plugin

import (
	"errors"
	"path/filepath"
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
	// a cached host from an earlier test would run under ITS mode: reset so
	// every test spawns under the mode it just set
	resetHostRegistry()
	t.Cleanup(resetHostRegistry)
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

// stderr written during an operation must reach the user's log exactly once
// per operation: a reused process must not re-warn lines it already warned
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
	assert.Contains(t, warned[0], "handling encrypt")
	assert.Contains(t, warned[1], "handling decrypt")
}

// the timeout is per operation, not a property of the shared host: a key
// borrowing a host first spawned under a much larger timeout must still fail
// on its own (much shorter) deadline, never on the first spawner's. k1 uses
// oneshot so the borrowed host is left holding a cleanly exited child: k2's
// request breaks its pipe, the clean-exit respawn path runs, and the fresh
// child (mode "never") hangs.
func TestTimeoutIsPerOperationNotFirstSpawners(t *testing.T) {
	bin := buildTestPlugin(t)
	allowTestPlugin(t, bin)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "oneshot")
	resetHostRegistry()
	t.Cleanup(resetHostRegistry)

	// first key spawns the shared host under a generous 10s
	k1 := NewMasterKey("testplugin", nil, 10*time.Second, bin)
	require.NoError(t, k1.Encrypt([]byte("datakey-0000000000000000")))

	// the respawned process hangs: the second key's 500ms deadline must win
	t.Setenv("SOPS_TESTPLUGIN_MODE", "never")
	k2 := NewMasterKey("testplugin", map[string]any{"other": true}, 500*time.Millisecond, bin)
	start := time.Now()
	err := k2.Encrypt([]byte("datakey-0000000000000000"))
	require.Error(t, err)
	// the error must name k2's own deadline; under the first spawner's 10s it
	// would read "timeout after 10s"
	assert.Contains(t, err.Error(), "timeout after 500ms")
	// the wall bound is loose on purpose: Windows tree-kill teardown runs
	// after the deadline fires and can burn its own bounded seconds
	assert.Less(t, time.Since(start), 8*time.Second, "the per-op timeout must beat the first spawner's 10s")
}

// process reuse: two MasterKeys on the same binary+path must share one plugin
// process. The procid mode bakes a per-process counter into key_ref, so equal
// refs prove one process and a changed ref proves a fresh spawn. The counter
// lives in a file pointed at by SOPS_TESTPLUGIN_PROCFILE: each spawn is a
// fresh process, so in-memory state cannot survive the exits.
func TestProcessReuseAcrossOperations(t *testing.T) {
	bin := buildTestPlugin(t)
	allowTestPlugin(t, bin)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "procid")
	t.Setenv("SOPS_TESTPLUGIN_PROCFILE", filepath.Join(t.TempDir(), "count"))
	resetHostRegistry()
	t.Cleanup(resetHostRegistry)

	k1 := NewMasterKey("testplugin", nil, 2*time.Second, bin)
	require.NoError(t, k1.Encrypt([]byte("datakey-0000000000000000")))
	assert.Equal(t, "testkey/proc1", k1.KeyRef)

	k2 := NewMasterKey("testplugin", map[string]any{"other": true}, 2*time.Second, bin)
	require.NoError(t, k2.Encrypt([]byte("datakey-0000000000000000")))
	assert.Equal(t, k1.KeyRef, k2.KeyRef, "two keys, one process")

	// the cache dies with a reset: the next operation spawns a new process
	ResetProcessCache()
	k3 := NewMasterKey("testplugin", nil, 2*time.Second, bin)
	require.NoError(t, k3.Encrypt([]byte("datakey-0000000000000000")))
	assert.Equal(t, "testkey/proc2", k3.KeyRef)
}

// with reuse the host outlives one operation: misbehavior must not carry a
// budget across ops, and a failed op must evict so the next op starts fresh
func TestBudgetIsPerOperation(t *testing.T) {
	bin := buildTestPlugin(t)
	allowTestPlugin(t, bin)
	t.Setenv("SOPS_TESTPLUGIN_MODE", "garbage")
	resetHostRegistry()
	t.Cleanup(resetHostRegistry)

	for i := 0; i < maxRestarts+2; i++ {
		k := NewMasterKey("testplugin", nil, 2*time.Second, bin)
		err := k.Encrypt([]byte("datakey-0000000000000000"))
		require.Error(t, err, "op %d", i)
		assert.Contains(t, err.Error(), "violation")
		assert.NotContains(t, err.Error(), "budget", "op %d", i)
	}

	// eviction, not a spent budget: with the plugin healthy again the very
	// next operation succeeds on a fresh spawn
	t.Setenv("SOPS_TESTPLUGIN_MODE", "")
	k := NewMasterKey("testplugin", nil, 2*time.Second, bin)
	require.NoError(t, k.Encrypt([]byte("datakey-0000000000000000")))
}
