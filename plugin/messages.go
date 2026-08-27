package plugin

import "fmt"

// Wire types for sops-plugin/1. Field order and JSON names are the contract.

type handshakeOut struct {
	Protocol   string `json:"protocol"`
	MaxVersion int    `json:"max_version"`
}

type handshakeIn struct {
	Protocol      string `json:"protocol"`
	Version       int    `json:"version"`
	Plugin        string `json:"plugin"`
	PluginVersion string `json:"plugin_version"`
}

type request struct {
	ID        int64          `json:"id"`
	Action    string         `json:"action"`
	Config    map[string]any `json:"config,omitempty"`
	Plaintext []byte         `json:"plaintext,omitempty"` // base64 on the wire
	Wrapped   string         `json:"wrapped,omitempty"`
}

type response struct {
	ID        int64        `json:"id"`
	OK        bool         `json:"ok"`
	Plaintext []byte       `json:"plaintext,omitempty"`
	Wrapped   string       `json:"wrapped,omitempty"`
	KeyRef    string       `json:"key_ref,omitempty"`
	Error     *pluginError `json:"error,omitempty"`
}

type pluginError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// MasterKey returns *pluginError as an error; v1 has no error wrapping.
func (e *pluginError) Error() string {
	return fmt.Sprintf("plugin error %s: %s", e.Code, e.Message)
}

// Frozen v1 error codes. ok:false is an answer, never a respawn trigger.
const (
	errCodeInvalidRequest    = "invalid_request"
	errCodeUnsupportedAction = "unsupported_action"
	errCodeConfigError       = "config_error"
	errCodeAuthFailed        = "auth_failed"
	errCodeKeyUnavailable    = "key_unavailable"
	errCodeInternal          = "internal"
)

const (
	protocolName    = "sops-plugin"
	protocolVersion = 1
)
