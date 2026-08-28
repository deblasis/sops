package plugin

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHost(t *testing.T, mode string) *host {
	t.Helper()
	bin := buildTestPlugin(t)
	allowTestPlugin(t, bin)
	t.Setenv("SOPS_TESTPLUGIN_MODE", mode)
	h := newHost("testplugin", bin, 2*time.Second)
	t.Cleanup(func() { h.kill() })
	return h
}

func wrapForTest(secret string) string {
	return "test.v1." + base64.StdEncoding.EncodeToString([]byte(secret))
}

func TestHandshakeNegotiation(t *testing.T) {
	h := newTestHost(t, "")
	require.NoError(t, h.start(context.Background()))
	assert.Equal(t, "1.2.3", h.pluginVersion)
	assert.NotEmpty(t, h.resolvedPath)
}

func TestHandshakeRejectsFutureVersion(t *testing.T) {
	h := newTestHost(t, "version_high")
	err := h.start(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, errVersionRefused), "got: %v", err)
	assert.Contains(t, err.Error(), "99")
	assert.Contains(t, err.Error(), "1")
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc := newTestHost(t, "")
	key := []byte("32-byte-data-key-aaaaaaaaaaaaaaaa")
	resp, err := enc.do(context.Background(), request{Action: "encrypt", Plaintext: key})
	require.NoError(t, err)
	require.True(t, resp.OK)
	assert.Equal(t, "testkey/primary", resp.KeyRef)
	assert.Equal(t, wrapForTest(string(key)), resp.Wrapped)

	dec := newTestHost(t, "")
	out, err := dec.do(context.Background(), request{Action: "decrypt", Wrapped: resp.Wrapped})
	require.NoError(t, err)
	require.True(t, out.OK)
	assert.Equal(t, key, out.Plaintext)
}

func TestOneshotPluginSurvivesManyKeys(t *testing.T) {
	h := newTestHost(t, "oneshot")
	for i := 0; i < 5; i++ {
		resp, err := h.do(context.Background(), request{
			Action:    "encrypt",
			Plaintext: []byte(wrapForTest("key-material-" + strings.Repeat("x", i))),
		})
		require.NoError(t, err, "encrypt %d", i)
		require.True(t, resp.OK)
		assert.Equal(t, "testkey/primary", resp.KeyRef)
	}
	// clean exits never drain the budget
	assert.Equal(t, 0, h.restarts)
}

func TestAuthFailureIsAnAnswerNotARespawn(t *testing.T) {
	h := newTestHost(t, "authfail")
	resp, err := h.do(context.Background(), request{Action: "decrypt", Wrapped: wrapForTest("x")})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.False(t, resp.OK)
	assert.Equal(t, errCodeAuthFailed, resp.Error.Code)
	assert.Equal(t, 0, h.restarts)
}

func TestGarbageCountsTowardBudget(t *testing.T) {
	h := newTestHost(t, "garbage")
	for i := 0; i < maxRestarts; i++ {
		_, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: []byte("k")})
		require.Error(t, err, "do %d", i)
	}
	_, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "budget")
}

func TestTimeoutKillsAndErrors(t *testing.T) {
	h := newTestHost(t, "never")
	start := time.Now()
	_, err := h.do(context.Background(), request{Action: "decrypt", Wrapped: wrapForTest("s")})
	elapsed := time.Since(start)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
	assert.Contains(t, err.Error(), "testplugin")
	assert.Contains(t, err.Error(), "decrypt")
	assert.Less(t, elapsed, 4*time.Second)
	assert.Nil(t, h.cmd, "timed-out process must be gone")
}

func TestUnflushedResponseTimesOut(t *testing.T) {
	h := newTestHost(t, "unflushed")
	_, err := h.do(context.Background(), request{Action: "decrypt", Wrapped: wrapForTest("s")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestWrongIDIsViolation(t *testing.T) {
	h := newTestHost(t, "wrongid")
	_, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "id")
}

func TestOversizedResponseRejected(t *testing.T) {
	h := newTestHost(t, "oversized")
	_, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
}

func TestStartupFailureIsFatalForKey(t *testing.T) {
	h := newTestHost(t, "exit1_startup")
	_, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errStartupFailed), "got: %v", err)
	// the child's pre-handshake stderr reason must ride along on the error
	assert.Contains(t, err.Error(), "stderr:")
	assert.Contains(t, err.Error(), "startup broke")
}

func TestHandshakeCleanExitRespawnsWithinCap(t *testing.T) {
	// exit 0 before any handshake byte is respawnable: never fatal, never
	// counted, but bounded by the per-operation spawn cap
	h := newTestHost(t, "clean_exit_startup")
	_, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spawn attempts")
	assert.Equal(t, 0, h.restarts, "clean exits never count against the budget")
}

func TestHandshakeTimeoutNamesPlugin(t *testing.T) {
	h := newTestHost(t, "hang_startup")
	start := time.Now()
	_, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: []byte("k")})
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
	_, err := h.do(ctx, request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "got: %v", err)
	assert.Less(t, time.Since(start), h.timeout, "ctx cancellation must beat the host timeout")
	assert.Equal(t, 0, h.restarts, "caller cancellation is not plugin misbehavior")
	assert.Nil(t, h.cmd, "abandoned child must still be killed")
}

func TestWriteTimeoutWhenChildNeverReads(t *testing.T) {
	// a payload far over any pipe buffer: the write cannot complete while
	// the child refuses to read, so the write deadline must fire
	h := newTestHost(t, "noread")
	start := time.Now()
	_, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: make([]byte, 256*1024)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.Contains(t, err.Error(), "encrypt")
	assert.Less(t, time.Since(start), 4*time.Second)
	assert.Nil(t, h.cmd, "wedged process must be gone")
	assert.Equal(t, 1, h.restarts, "a stalled write counts once, then fails")
}

func TestUnsolicitedLineIsViolation(t *testing.T) {
	h := newTestHost(t, "unsolicited")
	_, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "999")
	assert.Equal(t, 1, h.restarts)
}

// always exits 0 after reading the request: the respawn path must churn
// through the whole spawn cap and fail cleanly, never hang or panic
func TestCleanExitBeforeResponseBoundedBySpawnCap(t *testing.T) {
	h := newTestHost(t, "exit_clean_before_response")
	_, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spawn attempts")
}

// the child read the full request, then died non-zero: the wrap may already
// have been applied, so the operation must fail at once, naming the exit
// status and the child's stderr, and never resend
func TestCrashAfterRequestFailsWithoutResend(t *testing.T) {
	h := newTestHost(t, "crash_after_request")
	_, err := h.do(context.Background(), request{Action: "encrypt", Plaintext: []byte("k")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 7")
	assert.Contains(t, err.Error(), "crashed on purpose")
}

func TestNoKeyLeakInErrors(t *testing.T) {
	secret := "TOPSECRET-DATA-KEY"
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	for _, mode := range []string{"garbage", "never", "unflushed", "oversized", "wrongid"} {
		t.Run(mode, func(t *testing.T) {
			h := newTestHost(t, mode)
			_, err := h.do(context.Background(), request{Action: "decrypt", Wrapped: wrapForTest(secret)})
			require.Error(t, err)
			assert.NotContains(t, err.Error(), b64)
			assert.NotContains(t, err.Error(), secret)
		})
	}
}
