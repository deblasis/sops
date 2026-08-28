// Package plugin bridges sops master keys to out-of-process encryption
// backends speaking the sops-plugin/1 line protocol (docs/plugins/spec.md).
package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/getsops/sops/v3/keys"
)

var _ keys.MasterKey = (*MasterKey)(nil)

// MasterKey bridges sops to an external plugin binary. Config lives only in
// creation rules; metadata carries identity, never config.
type MasterKey struct {
	BinaryName     string
	PathOverride   string
	Config         map[string]any
	Timeout        time.Duration
	ExpectedKeyRef string // from creation rules; drives NeedsRotation
	WrappedKey     string
	KeyRef         string
	PluginVersion  string
	CreationDate   time.Time
}

func NewMasterKey(binaryName string, config map[string]any, timeout time.Duration, pathOverride string) *MasterKey {
	return &MasterKey{
		BinaryName:   binaryName,
		PathOverride: pathOverride,
		Config:       config,
		Timeout:      timeout,
		CreationDate: time.Now().UTC(),
	}
}

func (k *MasterKey) TypeToIdentifier() string { return "plugin" }

// dedup in config.go keys off this: binary + key identity, never type alone.
// ExpectedKeyRef fallback keeps identity stable from creation through decryption,
// since KeyRef stays empty until the plugin answers. Without any key ref, a
// digest of the (sorted, deterministic) marshaled config distinguishes
// same-binary keys.
func (k *MasterKey) ToString() string {
	ref := k.KeyRef
	if ref == "" {
		ref = k.ExpectedKeyRef
	}
	if ref != "" {
		return k.BinaryName + ":" + ref
	}
	if len(k.Config) > 0 {
		if b, err := json.Marshal(k.Config); err == nil {
			sum := sha256.Sum256(b)
			return k.BinaryName + ":" + hex.EncodeToString(sum[:4])
		}
	}
	return k.BinaryName
}

func (k *MasterKey) ToMap() map[string]any {
	return map[string]any{
		"binary_name":    k.BinaryName,
		"key_ref":        k.KeyRef,
		"enc":            k.WrappedKey,
		"created_at":     k.CreationDate.UTC().Format(time.RFC3339),
		"plugin_version": k.PluginVersion,
	}
}

func (k *MasterKey) SetEncryptedDataKey(b []byte) { k.WrappedKey = string(b) }
func (k *MasterKey) EncryptedDataKey() []byte     { return []byte(k.WrappedKey) }

func (k *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if k.WrappedKey == "" {
		return k.Encrypt(dataKey)
	}
	return nil
}

func (k *MasterKey) NeedsRotation() bool {
	if k.ExpectedKeyRef == "" {
		return false
	}
	return k.ExpectedKeyRef != k.KeyRef
}

func (k *MasterKey) Encrypt(dataKey []byte) error {
	// borrow, do not build: one host per binary per sops invocation, reused
	// across key operations (the age-plugin connection-reuse pattern); do()
	// serializes operations through the shared process
	h := registry.borrow(k.BinaryName, k.PathOverride, k.timeoutOr())
	resp, err := h.do(requestContext(), request{Action: "encrypt", Config: k.Config, Plaintext: dataKey})
	if err != nil {
		registry.discard(h)
		return err
	}
	version, warn := h.opSnapshot()
	registry.release(h)
	logStderr(k.BinaryName, warn)
	if err := k.answerError("encrypt", resp); err != nil {
		return err
	}
	if resp.Wrapped == "" {
		return &pluginError{Code: errCodeInternal, Message: fmt.Sprintf("plugin %s returned no wrapped key", k.BinaryName)}
	}
	k.WrappedKey = resp.Wrapped
	k.KeyRef = resp.KeyRef
	k.PluginVersion = version
	return nil
}

func (k *MasterKey) Decrypt() ([]byte, error) {
	if k.WrappedKey == "" {
		// fail before spawn: a keyless decrypt is caller error, not plugin work
		return nil, fmt.Errorf("plugin %s: no wrapped key to decrypt", k.BinaryName)
	}
	h := registry.borrow(k.BinaryName, k.PathOverride, k.timeoutOr())
	resp, err := h.do(requestContext(), request{Action: "decrypt", Wrapped: k.WrappedKey})
	if err != nil {
		registry.discard(h)
		return nil, err
	}
	_, warn := h.opSnapshot()
	registry.release(h)
	logStderr(k.BinaryName, warn)
	if err := k.answerError("decrypt", resp); err != nil {
		return nil, err
	}
	if len(resp.Plaintext) == 0 {
		return nil, &pluginError{Code: errCodeInternal, Message: fmt.Sprintf("plugin %s returned no plaintext", k.BinaryName)}
	}
	return resp.Plaintext, nil
}

// hostKey identifies a host the way newHost builds one: name plus override,
// since the same name can resolve to different binaries under an override.
type hostKey struct {
	binaryName   string
	pathOverride string
}

// hostRegistry caches one live host per plugin binary for the whole sops
// invocation: without it every key operation pays a fresh spawn, handshake,
// and credential resolution. Nothing evicts entries in production: children
// die with sops itself (Pdeathsig on linux, stdin EOF everywhere) and the
// registry only lives as long as the process.
type hostRegistry struct {
	mu    sync.Mutex
	hosts map[hostKey]*host
}

var registry = &hostRegistry{hosts: map[hostKey]*host{}}

// borrow returns the cached host for the binary, creating (but not spawning)
// one on first use; the spawn and handshake happen inside do.
func (r *hostRegistry) borrow(binaryName, pathOverride string, timeout time.Duration) *host {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := hostKey{binaryName, pathOverride}
	if h, ok := r.hosts[k]; ok {
		return h
	}
	h := newHost(binaryName, pathOverride, timeout)
	r.hosts[k] = h
	return h
}

// release returns a host after a successful operation. The timeout of the
// key that first spawned the host sticks for its lifetime: swapping it per
// operation would race the in-flight operation's deadline.
func (r *hostRegistry) release(h *host) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := hostKey{h.binaryName, h.pathOverride}
	if cur, ok := r.hosts[k]; !ok || cur == h {
		r.hosts[k] = h
		return
	}
	// a newer host took the slot after this one was discarded: retire the
	// surplus so one binary keeps one process
	h.kill()
}

// discard removes a host whose operation failed: the next operation on that
// binary spawns fresh, so a protocol violator never serves again.
func (r *hostRegistry) discard(h *host) {
	r.mu.Lock()
	k := hostKey{h.binaryName, h.pathOverride}
	if cur, ok := r.hosts[k]; ok && cur == h {
		delete(r.hosts, k)
	}
	r.mu.Unlock()
	h.kill()
}

func resetHostRegistry() {
	registry.mu.Lock()
	hosts := registry.hosts
	registry.hosts = map[hostKey]*host{}
	registry.mu.Unlock()
	for _, h := range hosts {
		h.kill()
	}
}

// ResetProcessCache kills and drops every cached plugin host. It exists for
// tests that change plugin-visible state (PATH, plugin environment) between
// operations; production never needs it, since a cached child's environment
// is fixed at spawn and the cache dies with the process.
func ResetProcessCache() { resetHostRegistry() }

// answerError validates the error-object half of the contract on a completed
// answer. Malformed answers fail the operation plainly (no respawn, no
// protocol-violation bookkeeping): the plugin answered, it just answered bad.
func (k *MasterKey) answerError(action string, resp *response) error {
	if resp.OK {
		if resp.Error != nil {
			return fmt.Errorf("plugin %s: %s: ok:true with an error object (code %q, message %q)",
				k.BinaryName, action, resp.Error.Code, resp.Error.Message)
		}
		return nil
	}
	if resp.Error == nil {
		return fmt.Errorf("plugin %s: %s: ok:false without an error object", k.BinaryName, action)
	}
	if resp.Error.Code == "" || resp.Error.Message == "" {
		return fmt.Errorf("plugin %s: %s: ok:false with an incomplete error object (code %q, message %q)",
			k.BinaryName, action, resp.Error.Code, resp.Error.Message)
	}
	e := resp.Error
	if !knownErrCodes[e.Code] {
		// spec section 6: a code outside the frozen list reads as internal
		e = &pluginError{Code: errCodeInternal, Message: e.Message}
	}
	return fmt.Errorf("plugin %s: %s: %w", k.BinaryName, action, e)
}

var knownErrCodes = map[string]bool{
	errCodeInvalidRequest:    true,
	errCodeUnsupportedAction: true,
	errCodeConfigError:       true,
	errCodeAuthFailed:        true,
	errCodeKeyUnavailable:    true,
	errCodeInternal:          true,
}

// stderrLogLimit keeps the surfaced stderr readable without spilling a chatty
// child's whole buffer into the log
const stderrLogLimit = 1024

// logStderr surfaces the stderr a completed operation captured. Warnings a
// plugin prints while otherwise succeeding (fake-mode notices, deprecations)
// must reach the user, not only crash errors.
func logStderr(binaryName, stderr string) {
	s := strings.TrimSpace(stderr)
	if s == "" {
		return
	}
	if len(s) > stderrLogLimit {
		s = s[:stderrLogLimit] + "...[truncated]"
	}
	log.Warnf("plugin %s stderr: %s", binaryName, s)
}

func (k *MasterKey) timeoutOr() time.Duration {
	if k.Timeout > 0 {
		return k.Timeout
	}
	if d, ok := globalTimeout(); ok {
		return d
	}
	return defaultTimeout
}

func requestContext() context.Context {
	return context.Background()
}
