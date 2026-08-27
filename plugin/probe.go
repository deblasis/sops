package plugin

import (
	"context"
	"fmt"
	"time"
)

// NewProbe builds a handshake-only probe against an explicit path. Listing is
// read-only diagnostics, so the allowlist gate does not apply; execution
// gating still guards key operations.
func NewProbe(path string) *Probe { return &Probe{path: path} }

type Probe struct{ path string }

// VersionSummary starts the binary, reads the handshake, and reports what it
// advertised. Never panics or blocks beyond a short timeout.
func (p *Probe) VersionSummary() string {
	h := newHost("probe", p.path, 3*time.Second)
	h.skipGate = true
	defer h.kill()
	if err := h.start(context.Background()); err != nil {
		return fmt.Sprintf("unreachable: %v", err)
	}
	return fmt.Sprintf("protocol %d, plugin %s %s", protocolVersion, h.pluginName, h.pluginVersion)
}

// CheckExecutable reports whether path is a native executable under the same
// rules as PATH resolution; shared with the CLI so verify rejects scripts the
// same way the host would.
func CheckExecutable(path string) bool { return isExecutableFile(path) }
