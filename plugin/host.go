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
// framing can never interleave. All state is guarded by mu.
type host struct {
	binaryName    string
	pathOverride  string
	timeout       time.Duration
	skipGate      bool // Task 12 conformance bypass for the allowlist gate
	resolvedPath  string
	cmd           *exec.Cmd
	stdin         io.WriteCloser
	stdout        *bufio.Reader
	stderr        *limitedBuffer
	pluginName    string
	pluginVersion string
	nextID        int64
	restarts      int
	mu            sync.Mutex
}

func newHost(binaryName, pathOverride string, timeout time.Duration) *host {
	return &host{binaryName: binaryName, pathOverride: pathOverride, timeout: timeout}
}

// ResetBudget clears the per-key restart counter; a new key starts clean.
func (h *host) ResetBudget() {
	h.mu.Lock()
	h.restarts = 0
	h.mu.Unlock()
}

func (h *host) start(ctx context.Context) error {
	if !h.skipGate {
		if err := gateExecution(h.binaryName); err != nil {
			return err
		}
	}
	path, err := resolvePlugin(h.binaryName, h.pathOverride)
	if err != nil {
		return err
	}
	h.resolvedPath = path
	cmd := exec.Command(path)
	cmd.Env = os.Environ()
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
	// kept across kill: the last child's stderr explains budget exhaustion
	h.stderr = &limitedBuffer{max: maxStderrBytes}
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
		h.kill()
		return fmt.Errorf("%w: plugin %s: handshake write: %v", errStartupFailed, h.binaryName, err)
	}
	hs, err := h.readHandshake(ctx)
	if err != nil {
		// a clean exit (status 0) before any handshake byte is respawnable,
		// same as a clean exit mid-session; every other handshake failure
		// (garbage, timeout, non-zero exit) is fatal
		if errors.Is(err, io.EOF) && h.exitedCleanly() {
			return errHandshakeCleanExit
		}
		h.kill()
		return err
	}
	if hs.Protocol != protocolName || hs.Plugin == "" {
		h.kill()
		return fmt.Errorf("%w: plugin %s: bad handshake fields from %s", errStartupFailed, h.binaryName, path)
	}
	if hs.Version > protocolVersion || hs.Version < 1 {
		h.kill()
		return fmt.Errorf("%w: plugin %s (%s %s) wants protocol version %d, sops supports 1..%d",
			errVersionRefused, h.binaryName, hs.Plugin, hs.PluginVersion, hs.Version, protocolVersion)
	}
	h.pluginName = hs.Plugin
	h.pluginVersion = hs.PluginVersion
	return nil
}

// readLineWithin reads one stdout line under the host timeout and ctx. The
// reader is captured before launching so an abandoned goroutine can never
// touch the NEXT spawn's stdout after a timeout respawn.
func (h *host) readLineWithin(ctx context.Context, what string) ([]byte, error) {
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
	timer := time.NewTimer(h.timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.line, r.err
	case <-timer.C:
		h.kill()
		return nil, fmt.Errorf("plugin %s: timeout after %v during %s", h.binaryName, h.timeout, what)
	case <-ctx.Done():
		h.kill()
		return nil, fmt.Errorf("plugin %s: abandoned during %s: %w", h.binaryName, what, ctx.Err())
	}
}

// writeLineWithin writes one request line under the same timeout discipline
// as reads: a child that hands successfully but never reads stdin must not
// pin sops on a full pipe. The writer handle is captured so an abandoned
// goroutine can only ever touch this spawn's stdin.
func (h *host) writeLineWithin(ctx context.Context, req request) error {
	type writeRes struct{ err error }
	ch := make(chan writeRes, 1)
	w := h.stdin
	go func() { ch <- writeRes{writeLine(w, req)} }()
	timer := time.NewTimer(h.timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.err
	case <-timer.C:
		h.kill()
		return fmt.Errorf("plugin %s: %w after %v writing %q request", h.binaryName, errWriteTimeout, h.timeout, req.Action)
	case <-ctx.Done():
		h.kill()
		return fmt.Errorf("plugin %s: abandoned writing %q request: %w", h.binaryName, req.Action, ctx.Err())
	}
}

func (h *host) readHandshake(ctx context.Context) (handshakeIn, error) {
	line, err := h.readLineWithin(ctx, "handshake")
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
	if h.cmd == nil || h.cmd.Process == nil {
		return false
	}
	killTree(h.cmd)
	if h.stdin != nil {
		h.stdin.Close()
	}
	err := h.cmd.Wait()
	h.cmd, h.stdin, h.stdout = nil, nil, nil
	return err == nil
}

// do runs one lockstep request. Restart accounting:
//   - clean exit (EOF, no partial line) before any response byte: respawn and
//     resend WITHOUT counting; clean exits after complete responses likewise
//     never count, so one-shot plugins survive any number of keys
//   - garbage output, partial lines, timeouts, id mismatches: count toward
//     maxRestarts and are never resent (a resend could double-apply)
//   - ok:false is an answer, not a respawn trigger
func (h *host) do(ctx context.Context, req request) (*response, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	attempts := 0
	for {
		attempts++
		// bound respawns even when nothing counts (plugin that exits cleanly
		// forever must not hang sops)
		if attempts > 2*(maxRestarts+1) {
			return nil, fmt.Errorf("plugin %s: gave up after %d spawn attempts for action %q", h.binaryName, attempts-1, req.Action)
		}
		if h.cmd == nil || h.cmd.Process == nil {
			if h.restarts >= maxRestarts {
				return nil, fmt.Errorf("plugin %s: restart budget exhausted after %d restarts (stderr: %s)",
					h.binaryName, h.restarts, h.stderrString())
			}
			if err := h.start(ctx); err != nil {
				if errors.Is(err, errHandshakeCleanExit) {
					// clean exit at the handshake: respawn within the spawn
					// cap above, never counted against the restart budget
					continue
				}
				return nil, err
			}
		}
		req.ID = h.nextID
		h.nextID++
		if err := h.writeLineWithin(ctx, req); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err // caller gave up: not plugin misbehavior, do not count
			}
			if errors.Is(err, errWriteTimeout) {
				// a full pipe is plugin misbehavior: counted, never resent
				h.kill()
				h.restarts++
				return nil, err
			}
			// stdin broke: either a cleanly-exited one-shot child (EPIPE) or a
			// real spawn failure; respawn sorts out which without counting
			h.kill()
			continue
		}
		resp, err := h.readResponse(ctx, req.ID, req.Action)
		if err == nil {
			return resp, nil
		}
		if errors.Is(err, io.EOF) {
			h.kill()
			continue // clean death before any response byte: resend on a fresh child
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			h.kill()
			return nil, err // caller gave up: not plugin misbehavior, do not count
		}
		h.kill()
		h.restarts++
		return nil, err
	}
}

// readResponse reads one response line. It returns io.EOF (unwrapped) when the
// child died before emitting any byte: do() treats that as respawnable.
func (h *host) readResponse(ctx context.Context, id int64, action string) (*response, error) {
	line, err := h.readLineWithin(ctx, fmt.Sprintf("%q response", action))
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

// kill destroys the process tree and detaches all pipes. Idempotent.
// Counting toward the restart budget is the caller's job: only some deaths
// count (see do).
func (h *host) kill() {
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

func (l *limitedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.buf.String()
	if l.truncated {
		s += "...[truncated]"
	}
	return s
}
