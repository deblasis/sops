package plugin

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	maxRestarts     = 3
	maxLineBytes    = 1024 * 1024
	maxStderrBytes  = 8 * 1024
	stdoutErrPrefix = 256
	defaultTimeout  = 30 * time.Second
)

var (
	errStartupFailed      = errors.New("plugin failed during startup")
	errVersionRefused     = errors.New("plugin protocol version refused")
	errHandshakeCleanExit = errors.New("plugin exited cleanly before the handshake")
	errWriteTimeout       = errors.New("request write timed out")
)

// host owns one plugin binary. Lockstep: a single outstanding request, so
// framing can never interleave. All state is guarded by mu. The host carries
// no timeout of its own: every operation runs under the deadline its caller
// passes to do(), so a shared process serves each key under that key's own
// timeout (spec section 10).
type host struct {
	binaryName    string
	pathOverride  string
	skipGate      bool // diagnostics (verify, probe) name the binary explicitly; they bypass the allowlist gate
	resolvedPath  string
	cmd           *exec.Cmd
	stdin         io.WriteCloser
	stdout        *bufio.Reader
	stderr        *limitedBuffer
	pluginName    string
	pluginVersion string
	nextID        int64
	stderrMark    int // stderr bytes already surfaced: a reused process warns once per line
	mu            sync.Mutex
}

func newHost(binaryName, pathOverride string) *host {
	return &host{binaryName: binaryName, pathOverride: pathOverride}
}

func (h *host) start(ctx context.Context, timeout time.Duration) error {
	path, err := resolvePlugin(h.binaryName, h.pathOverride)
	if err != nil {
		return err
	}
	h.resolvedPath = path
	if !h.skipGate {
		// gated after resolution: the override check needs the resolved path
		if err := gateExecution(h.binaryName, h.resolvedPath, h.pathOverride); err != nil {
			return err
		}
	}
	cmd := exec.Command(path)
	cmd.Env = os.Environ()
	// never the repo as working directory: a plugin sniffing its cwd must not
	// see repository content
	cmd.Dir = os.TempDir()
	setChildAttrs(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return err
	}
	// kept across kill: the last child's stderr explains its death
	h.stderr = &limitedBuffer{max: maxStderrBytes}
	h.stderrMark = 0
	cmd.Stderr = h.stderr
	if err := cmd.Start(); err != nil {
		stdin.Close()
		return fmt.Errorf("%w: %v", errStartupFailed, err)
	}
	h.cmd = cmd
	h.stdin = stdin
	h.stdout = bufio.NewReader(stdoutPipe) // fresh per spawn: never splice output across processes
	h.nextID = 1                           // ids restart at 1 per spawn
	if err := writeLine(h.stdin, handshakeOut{Protocol: protocolName, MaxVersion: protocolVersion}); err != nil {
		h.killLocked()
		return fmt.Errorf("%w: plugin %s: handshake write: %v%s", errStartupFailed, h.binaryName, err, h.startupStderr())
	}
	hs, err := h.readHandshake(ctx, timeout)
	if err != nil {
		// a clean exit (status 0) before any handshake byte is respawnable,
		// same as a clean exit mid-session; every other handshake failure
		// (garbage, timeout, non-zero exit) is fatal
		if errors.Is(err, io.EOF) && h.exitedCleanly() {
			return errHandshakeCleanExit
		}
		h.killLocked()
		if suffix := h.startupStderr(); suffix != "" {
			return fmt.Errorf("%w%s", err, suffix)
		}
		return err
	}
	if hs.Protocol != protocolName || hs.Plugin == "" {
		h.killLocked()
		return fmt.Errorf("%w: plugin %s: bad handshake fields from %s%s", errStartupFailed, h.binaryName, path, h.startupStderr())
	}
	if hs.Version > protocolVersion || hs.Version < 1 {
		h.killLocked()
		return fmt.Errorf("%w: plugin %s (%s %s) wants protocol version %d, sops supports 1..%d%s",
			errVersionRefused, h.binaryName, hs.Plugin, hs.PluginVersion, hs.Version, protocolVersion, h.startupStderr())
	}
	h.pluginName = hs.Plugin
	h.pluginVersion = hs.PluginVersion
	return nil
}

// readLineWithin reads one stdout line under the operation's deadline and
// ctx. The reader is captured before launching so an abandoned goroutine can
// never touch the NEXT spawn's stdout after a timeout respawn.
func (h *host) readLineWithin(ctx context.Context, timeout time.Duration, what string) ([]byte, error) {
	type readRes struct {
		line []byte
		err  error
	}
	ch := make(chan readRes, 1)
	rdr := h.stdout
	go func() {
		line, err := readLine(rdr, maxLineBytes)
		ch <- readRes{line, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.line, r.err
	case <-timer.C:
		h.killLocked()
		return nil, fmt.Errorf("plugin %s: timeout after %v during %s", h.binaryName, timeout, what)
	case <-ctx.Done():
		h.killLocked()
		return nil, fmt.Errorf("plugin %s: abandoned during %s: %w", h.binaryName, what, ctx.Err())
	}
}

// writeLineWithin writes one request line under the same timeout discipline
// as reads: a child that hands successfully but never reads stdin must not
// pin sops on a full pipe. The writer handle is captured so an abandoned
// goroutine can only ever touch this spawn's stdin.
func (h *host) writeLineWithin(ctx context.Context, timeout time.Duration, req request) error {
	type writeRes struct{ err error }
	ch := make(chan writeRes, 1)
	w := h.stdin
	go func() { ch <- writeRes{writeLine(w, req)} }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.err
	case <-timer.C:
		h.killLocked()
		return fmt.Errorf("plugin %s: %w after %v writing %q request", h.binaryName, errWriteTimeout, timeout, req.Action)
	case <-ctx.Done():
		h.killLocked()
		return fmt.Errorf("plugin %s: abandoned writing %q request: %w", h.binaryName, req.Action, ctx.Err())
	}
}

func (h *host) readHandshake(ctx context.Context, timeout time.Duration) (handshakeIn, error) {
	line, err := h.readLineWithin(ctx, timeout, "handshake")
	if err != nil {
		// a raw read error stays distinguishable (io.EOF etc.); timeout and
		// ctx abandonment are already terminal messages of their own
		return handshakeIn{}, fmt.Errorf("%w: plugin %s: %w", errStartupFailed, h.binaryName, err)
	}
	var hs handshakeIn
	if err := decodeInto(line, &hs); err != nil {
		return handshakeIn{}, fmt.Errorf("%w: plugin %s: %v", errStartupFailed, h.binaryName, err)
	}
	return hs, nil
}

// exitedCleanly tears the child down and reports whether it had ALREADY
// exited with status 0. A child still alive (or dead non-zero) reads as
// unclean: only an observed clean EOF plus a zero exit status is respawnable.
func (h *host) exitedCleanly() bool {
	return h.reap() == nil
}

// reap tears the child down with exactly one Wait and returns the Wait
// error: nil iff the child had already exited with status 0. killTree runs
// first so a child that closed its pipes but lingers cannot outlive the
// call. Must be called with mu held (every do() path) or from the only
// goroutine using the host, as in tests and conformance.
func (h *host) reap() error {
	if h.cmd == nil || h.cmd.Process == nil {
		return errors.New("plugin process already gone")
	}
	killTree(h.cmd)
	if h.stdin != nil {
		h.stdin.Close()
	}
	err := h.cmd.Wait()
	h.cmd, h.stdin, h.stdout = nil, nil, nil
	return err
}

// crashError explains a child that died non-zero before answering. The exit
// status and the child's captured stderr are the whole diagnosis; the
// request is never resent (the wrap may already have been applied).
func (h *host) crashError(action string, werr error) error {
	code := -1
	var ee *exec.ExitError
	if errors.As(werr, &ee) {
		code = ee.ExitCode()
	}
	return fmt.Errorf("plugin %s: exited with status %d before answering action %q; request not resent%s",
		h.binaryName, code, action, h.startupStderr())
}

// do runs one lockstep request under the caller's timeout. Failure accounting
// is per call: the host is shared across operations (see key.go), so nothing
// may leak from one operation's misbehavior into the next, and the deadline
// is per operation too, never stored on the shared host.
//   - clean exit (status 0, no partial line) before any response byte,
//     whether it reads as EOF on stdout or a broken stdin pipe: respawn and
//     resend, never counted; clean exits after complete responses likewise
//     never count, so one-shot plugins survive any number of keys
//   - non-zero exit before any response byte: fail immediately and NEVER
//     resend (the wrap may already have been applied)
//   - garbage output, partial lines, timeouts, id mismatches: fail
//     immediately, never resent (a resend could double-apply)
//   - ok:false is an answer, not a respawn trigger
func (h *host) do(ctx context.Context, timeout time.Duration, req request) (*response, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	attempts := 0
	for {
		attempts++
		// bound respawns even when nothing counts (plugin that exits cleanly
		// forever must not hang sops)
		if attempts > 2*(maxRestarts+1) {
			return nil, fmt.Errorf("plugin %s: gave up after %d spawn attempts for action %q%s",
				h.binaryName, attempts-1, req.Action, h.startupStderr())
		}
		if h.cmd == nil || h.cmd.Process == nil {
			if err := h.start(ctx, timeout); err != nil {
				if errors.Is(err, errHandshakeCleanExit) {
					// clean exit at the handshake: respawn within the spawn
					// cap above, never counted
					continue
				}
				return nil, err
			}
		}
		req.ID = h.nextID
		h.nextID++
		if err := h.writeLineWithin(ctx, timeout, req); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err // caller gave up: not plugin misbehavior
			}
			if errors.Is(err, errWriteTimeout) {
				// a full pipe is plugin misbehavior: fail, never resend
				h.killLocked()
				return nil, err
			}
			// stdin broke mid-write: a child that exited cleanly is
			// respawnable, one that died non-zero may already have applied
			// the wrap and must never see the request again
			werr := h.reap()
			if werr == nil {
				continue
			}
			return nil, h.crashError(req.Action, werr)
		}
		resp, err := h.readResponse(ctx, timeout, req.ID, req.Action)
		if err == nil {
			return resp, nil
		}
		if errors.Is(err, io.EOF) {
			// stdout closed before any response byte: whether that is a
			// respawnable clean exit or a crash that must not be resent is
			// decided by the reaped exit status, not by the EOF itself
			werr := h.reap()
			if werr == nil {
				continue // clean death before any response byte: resend on a fresh child
			}
			return nil, h.crashError(req.Action, werr)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			h.killLocked()
			return nil, err // caller gave up: not plugin misbehavior
		}
		h.killLocked()
		return nil, err
	}
}

// readResponse reads one response line. It returns io.EOF (unwrapped) when the
// child died before emitting any byte: do() treats that as respawnable.
func (h *host) readResponse(ctx context.Context, timeout time.Duration, id int64, action string) (*response, error) {
	line, err := h.readLineWithin(ctx, timeout, fmt.Sprintf("%q response", action))
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		// timeout/ctx abandonment arrive as their own terminal errors; only
		// read violations carry no stdout bytes: once a response line has
		// begun, its bytes must not reach errors
		return nil, err
	}
	var resp response
	if err := decodeInto(line, &resp); err != nil {
		// complete garbage line: a bounded prefix is safe to show
		return nil, h.violation(action, err, prefixOf(line, stdoutErrPrefix))
	}
	if resp.ID != id {
		return nil, fmt.Errorf("plugin %s: response id %d does not match request id %d for action %q",
			h.binaryName, resp.ID, id, action)
	}
	return &resp, nil
}

func (h *host) violation(action string, err error, rawPrefix string) error {
	if rawPrefix != "" {
		return fmt.Errorf("plugin %s: protocol violation on %q: %v (stdout: %s)", h.binaryName, action, err, rawPrefix)
	}
	return fmt.Errorf("plugin %s: protocol violation on %q: %v", h.binaryName, action, err)
}

func (h *host) stderrString() string {
	if h.stderr == nil {
		return ""
	}
	return h.stderr.String()
}

// startupStderr explains a fatal startup in the child's own words, capped
// like the per-operation stderr log so a chatty child cannot flood the error
func (h *host) startupStderr() string {
	s := strings.TrimSpace(h.stderrString())
	if s == "" {
		return ""
	}
	if len(s) > stderrLogLimit {
		s = s[:stderrLogLimit] + "...[truncated]"
	}
	return "; stderr: " + s
}

// kill destroys the process tree and detaches all pipes. Idempotent. Takes
// mu, so it is safe against an operation in flight on the host (the registry
// kills discarded hosts this way).
func (h *host) kill() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.killLocked()
}

// killLocked is kill for callers already holding mu: every path inside do().
func (h *host) killLocked() {
	if h.cmd == nil {
		return
	}
	killTree(h.cmd)
	if h.stdin != nil {
		h.stdin.Close()
	}
	h.cmd.Wait() // reaps the child; exit status is not interesting here
	h.cmd = nil
	h.stdin = nil
	h.stdout = nil
}

// opSnapshot captures post-operation state under the lock. Once the host is
// back in the registry another key's operation may respawn it and rewrite
// these fields, so callers must snapshot before releasing. Marking stderr
// keeps a reused process from re-warning the same lines on every operation.
func (h *host) opSnapshot() (version, stderr string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, mark := h.stderr.since(h.stderrMark)
	h.stderrMark = mark
	return h.pluginVersion, s
}

// prefixOf renders at most n bytes of raw stdout; garbage must never reach an
// error whole, it can echo key material.
func prefixOf(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...[truncated]"
}

// limitedBuffer caps captured stderr so a chatty child cannot balloon memory.
type limitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	room := l.max - l.buf.Len()
	if room <= 0 {
		l.truncated = true
		return len(p), nil // lie about storing: the child must not block on stderr
	}
	if len(p) > room {
		l.buf.Write(p[:room])
		l.truncated = true
		return len(p), nil
	}
	l.buf.Write(p)
	return len(p), nil
}

// since returns the bytes appended after the given mark plus the new mark;
// a mark past the cap reads as "nothing new", the dropped bytes are gone
func (l *limitedBuffer) since(mark int) (string, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buf.Bytes()
	if mark > len(b) {
		mark = len(b)
	}
	return string(b[mark:]), len(b)
}

func (l *limitedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.buf.String()
	if l.truncated {
		s += "...[truncated]"
	}
	return s
}
