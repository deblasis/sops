package plugin

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the deadline every direct host test runs its operations
// under: the host carries no timeout of its own anymore.
const testTimeout = 2 * time.Second

func newTestHost(t *testing.T, mode string) *host {
	t.Helper()
	bin := buildTestPlugin(t)
	allowTestPlugin(t, bin)
	t.Setenv("SOPS_TESTPLUGIN_MODE", mode)
	h := newHost("testplugin", bin)
	t.Cleanup(func() { h.kill() })
	return h
}

func wrapForTest(secret string) string {
	return "test.v1." + base64.StdEncoding.EncodeToString([]byte(secret))
}

func TestHandshakeNegotiation(t *testing.T) {
	h := newTestHost(t, "")
	require.NoError(t, h.start(context.Background(), testTimeout))
	assert.Equal(t, "1.2.3", h.pluginVersion)
	assert.NotEmpty(t, h.resolvedPath)
}

func TestHandshakeRejectsFutureVersion(t *testing.T) {
	h := newTestHost(t, "version_high")
	err := h.start(context.Background(), testTimeout)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errVersionRefused), "got: %v", err)
	assert.Contains(t, err.Error(), "99")
	assert.Contains(t, err.Error(), "1")
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc := newTestHost(t, "")
	key := []byte("32-byte-data-key-aaaaaaaaaaaaaaaa")
	resp, err := enc.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: key})
	require.NoError(t, err)
	require.True(t, resp.OK)
	assert.Equal(t, "testkey/primary", resp.KeyRef)
	assert.Equal(t, wrapForTest(string(key)), resp.Wrapped)

	dec := newTestHost(t, "")
	out, err := dec.do(context.Background(), testTimeout, request{Action: "decrypt", Wrapped: resp.Wrapped})
	require.NoError(t, err)
	require.True(t, out.OK)
	assert.Equal(t, key, out.Plaintext)
}

func TestOneshotPluginSurvivesManyKeys(t *testing.T) {
	h := newTestHost(t, "oneshot")
	for i := 0; i < 5; i++ {
		resp, err := h.do(context.Background(), testTimeout, request{
			Action:    "encrypt",
			Plaintext: []byte(wrapForTest("key-material-" + strings.Repeat("x", i))),
		})
		require.NoError(t, err, "encrypt %d", i)
		require.True(t, resp.OK)
		assert.Equal(t, "testkey/primary", resp.KeyRef)
	}
	// every op crossed a clean exit and a respawn: clean exits never fail an op
}

func TestAuthFailureIsAnAnswerNotARespawn(t *testing.T) {
	h := newTestHost(t, "authfail")
	resp, err := h.do(context.Background(), testTimeout, request{Action: "decrypt", Wrapped: wrapForTest("x")})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.False(t, resp.OK)
	assert.Equal(t, errCodeAuthFailed, resp.Error.Code)
}

// failure accounting is per operation: a shared host must not accumulate
// misbehavior across ops, each violation fails its own operation at once
func TestGarbageFailsEveryOperationImmediately(t *testing.T) {
	h := newTestHost(t, "garbage")
	for i := 0; i < maxRestarts+2; i++ {
		_, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: []byte("k")})
		require.Error(t, err, "do %d", i)
		assert.Contains(t, err.Error(), "violation")
		assert.NotContains(t, err.Error(), "budget", "op %d", i)
	}
}

func TestTimeoutKillsAndErrors(t *testing.T) {
	h := newTestHost(t, "never")
	start := time.Now()
	_, err := h.do(context.Background(), testTimeout, request{Action: "decrypt", Wrapped: wrapForTest("s")})
	elapsed := time.Since(start)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
	assert.Contains(t, err.Error(), "testplugin")
	assert.Contains(t, err.Error(), "decrypt")
	// the wall bound is loose on purpose: Windows tree-kill teardown runs
	// after the deadline fires and can burn its own bounded seconds
	assert.Less(t, elapsed, 8*time.Second)
	assert.Nil(t, h.cmd, "timed-out process must be gone")
}

func TestUnflushedResponseTimesOut(t *testing.T) {
	h := newTestHost(t, "unflushed")
	_, err := h.do(context.Background(), testTimeout, request{Action: "decrypt", Wrapped: wrapForTest("s")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestWrongIDIsViolation(t *testing.T) {
	h := newTestHost(t, "wrongid")
	_, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "id")
}

// an oversized line is a violation that fails the op at once: the cap is
// named on the error and the request is never resent (exactly one spawn)
func TestOversizedResponseRejected(t *testing.T) {
	countPath := filepath.Join(t.TempDir(), "count")
	t.Setenv("SOPS_TESTPLUGIN_PROCFILE", countPath)
	h := newTestHost(t, "oversized")
	_, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line exceeds protocol cap")
	got, rerr := os.ReadFile(countPath)
	require.NoError(t, rerr)
	assert.Equal(t, "1", strings.TrimSpace(string(got)))
}

func TestStartupFailureIsFatalForKey(t *testing.T) {
	h := newTestHost(t, "exit1_startup")
	_, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errStartupFailed), "got: %v", err)
	// the child's pre-handshake stderr reason must ride along on the error
	assert.Contains(t, err.Error(), "stderr:")
	assert.Contains(t, err.Error(), "startup broke")
}

func TestHandshakeCleanExitRespawnsWithinCap(t *testing.T) {
	// exit 0 before any handshake byte is respawnable: never fatal, but
	// bounded by the per-operation spawn cap
	h := newTestHost(t, "clean_exit_startup")
	_, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spawn attempts")
}

func TestHandshakeTimeoutNamesPlugin(t *testing.T) {
	h := newTestHost(t, "hang_startup")
	start := time.Now()
	_, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errStartupFailed), "got: %v", err)
	assert.Contains(t, err.Error(), "testplugin")
	assert.Less(t, time.Since(start), 4*time.Second)
}

func TestContextCancelAbandonsPromptlyWithoutCounting(t *testing.T) {
	h := newTestHost(t, "never")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := h.do(ctx, testTimeout, request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "got: %v", err)
	assert.Less(t, time.Since(start), testTimeout, "ctx cancellation must beat the host timeout")
	assert.Nil(t, h.cmd, "abandoned child must still be killed")
}

func TestWriteTimeoutWhenChildNeverReads(t *testing.T) {
	// a payload far over any pipe buffer: the write cannot complete while
	// the child refuses to read, so the write deadline must fire
	h := newTestHost(t, "noread")
	start := time.Now()
	_, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: make([]byte, 256*1024)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.Contains(t, err.Error(), "encrypt")
	// loose wall bound: Windows tree-kill teardown runs after the deadline
	// and can burn its own seconds under load (see TestTimeoutKillsAndErrors)
	assert.Less(t, time.Since(start), 8*time.Second)
	assert.Nil(t, h.cmd, "wedged process must be gone")
}

func TestUnsolicitedLineIsViolation(t *testing.T) {
	h := newTestHost(t, "unsolicited")
	_, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "999")
}

// always exits 0 after reading the request: the respawn path must churn
// through the whole spawn cap and fail cleanly, never hang or panic
func TestCleanExitBeforeResponseBoundedBySpawnCap(t *testing.T) {
	h := newTestHost(t, "exit_clean_before_response")
	_, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spawn attempts")
}

// the child read the full request, then died non-zero: the wrap may already
// have been applied, so exactly one spawn and no resend; the exit status and
// the child's stderr must name the crash
func TestCrashAfterRequestFailsWithoutResend(t *testing.T) {
	countPath := filepath.Join(t.TempDir(), "count")
	t.Setenv("SOPS_TESTPLUGIN_PROCFILE", countPath)
	h := newTestHost(t, "crash_after_request")
	_, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 7")
	assert.Contains(t, err.Error(), "crashed on purpose")
	// exactly one spawn: a resend would have bumped the counter twice
	got, rerr := os.ReadFile(countPath)
	require.NoError(t, rerr)
	assert.Equal(t, "1", strings.TrimSpace(string(got)))
}

// the write-side twin of the crash test above: the child dies non-zero
// without ever reading the request, so the write breaks against a dead pipe.
// Same contract: exactly one spawn, no resend, exit status + stderr named.
// The oversized payload keeps the write in flight while the child exits, so
// the EPIPE branch is the one that fires.
func TestCrashBeforeRequestFailsWithoutResend(t *testing.T) {
	countPath := filepath.Join(t.TempDir(), "count")
	t.Setenv("SOPS_TESTPLUGIN_PROCFILE", countPath)
	h := newTestHost(t, "crash_before_request")
	_, err := h.do(context.Background(), testTimeout, request{Action: "encrypt", Plaintext: make([]byte, 256*1024)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 7")
	assert.Contains(t, err.Error(), "crashed on purpose")
	got, rerr := os.ReadFile(countPath)
	require.NoError(t, rerr)
	assert.Equal(t, "1", strings.TrimSpace(string(got)))
}

func TestNoKeyLeakInErrors(t *testing.T) {
	secret := "TOPSECRET-DATA-KEY"
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	for _, mode := range []string{"garbage", "never", "unflushed", "oversized", "wrongid"} {
		t.Run(mode, func(t *testing.T) {
			h := newTestHost(t, mode)
			_, err := h.do(context.Background(), testTimeout, request{Action: "decrypt", Wrapped: wrapForTest(secret)})
			require.Error(t, err)
			assert.NotContains(t, err.Error(), b64)
			assert.NotContains(t, err.Error(), secret)
		})
	}
}
