package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

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
	h := newHost(k.BinaryName, k.PathOverride, k.timeoutOr())
	defer h.kill()
	h.ResetBudget()
	resp, err := h.do(requestContext(), request{Action: "encrypt", Config: k.Config, Plaintext: dataKey})
	if err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error != nil {
			return fmt.Errorf("plugin %s: encrypt: %w", k.BinaryName, resp.Error)
		}
		return fmt.Errorf("plugin %s: encrypt: ok:false without error object", k.BinaryName)
	}
	if resp.Wrapped == "" {
		return &pluginError{Code: errCodeInternal, Message: "plugin returned no wrapped key"}
	}
	k.WrappedKey = resp.Wrapped
	k.KeyRef = resp.KeyRef
	k.PluginVersion = h.pluginVersion
	return nil
}

func (k *MasterKey) Decrypt() ([]byte, error) {
	if k.WrappedKey == "" {
		// fail before spawn: a keyless decrypt is caller error, not plugin work
		return nil, fmt.Errorf("plugin %s: no wrapped key to decrypt", k.BinaryName)
	}
	h := newHost(k.BinaryName, k.PathOverride, k.timeoutOr())
	defer h.kill()
	h.ResetBudget()
	resp, err := h.do(requestContext(), request{Action: "decrypt", Wrapped: k.WrappedKey})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		if resp.Error != nil {
			return nil, fmt.Errorf("plugin %s: decrypt: %w", k.BinaryName, resp.Error)
		}
		return nil, fmt.Errorf("plugin %s: decrypt: ok:false without error object", k.BinaryName)
	}
	if len(resp.Plaintext) == 0 {
		return nil, &pluginError{Code: errCodeInternal, Message: "plugin returned no plaintext"}
	}
	return resp.Plaintext, nil
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
