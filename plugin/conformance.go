package plugin

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Positive-only conformance: a third-party binary cannot simulate the
// testplugin's misbehavior modes, so misbehavior coverage lives in the package
// test suite; here every check must simply succeed.
const (
	conformanceTimeout = 10 * time.Second
	bogusWrapped       = "sops-conformance-bogus.v1.!!!!!"
	probeLen           = 32
)

// semver-ish: v-prefixed dotted numbers, at least one digit
var semverishRe = regexp.MustCompile(`^[vV]?\d+(\.\d+){0,3}`)

type ConformanceResult struct {
	Name   string
	Pass   bool
	Detail string
}

func (r *ConformanceResult) fail(detail string) {
	r.Pass, r.Detail = false, detail
}

func (r *ConformanceResult) ok(detail string) {
	r.Pass, r.Detail = true, detail
}

// RunConformance exercises a plugin binary end to end: handshake, encrypt /
// decrypt lockstep round trip, error-object shape on a bogus blob, and a
// repeat that also crosses a respawn. The allowlist gate is bypassed: the
// caller named this binary explicitly on the CLI.
func RunConformance(path string) []ConformanceResult {
	res := []ConformanceResult{
		{Name: "handshake"},
		{Name: "roundtrip"},
		{Name: "error-shape"},
		{Name: "repeat"},
	}
	ctx := context.Background()
	// derived purely for readable error messages; the path is authoritative
	name := strings.TrimPrefix(strings.TrimSuffix(filepath.Base(path), ".exe"), "sops-plugin-")
	if validateBinaryName(name) != nil {
		name = "conformance"
	}
	h := newHost(name, path, conformanceTimeout)
	h.skipGate = true
	defer h.kill()

	if err := h.start(ctx); err != nil {
		res[0].fail(err.Error())
		for i := 1; i < len(res); i++ {
			res[i].fail("not run: handshake failed")
		}
		return res
	}
	res[0].ok(fmt.Sprintf("protocol %d, plugin %s %s", protocolVersion, h.pluginName, h.pluginVersion))
	if !semverishRe.MatchString(h.pluginVersion) {
		res[0].fail(fmt.Sprintf("plugin_version %q is not semver-ish", h.pluginVersion))
	}

	// probe A ramps 1..32, probe B spans the full byte range 0x00..0xFF:
	// distinct probes catch last-plaintext-echoing plugins, B catches NUL and
	// high-byte mangling. Deterministic: a conformance probe is not a secret.
	probeA := make([]byte, probeLen)
	probeB := make([]byte, probeLen)
	for i := range probeA {
		probeA[i] = byte(i + 1)
		probeB[i] = byte(i * 0xFF / (probeLen - 1))
	}

	runRoundTrip(ctx, h, probeA, probeB, &res[1])
	runErrorShape(ctx, h, &res[2])
	runRepeat(ctx, h, probeA, &res[3])
	return res
}

func runRoundTrip(ctx context.Context, h *host, a, b []byte, r *ConformanceResult) {
	encA, err := h.do(ctx, request{Action: "encrypt", Plaintext: a})
	switch {
	case err != nil:
		r.fail(err.Error())
		return
	case !encA.OK:
		r.fail(answerDetail("encrypt", encA))
		return
	case encA.Wrapped == "" || encA.Wrapped == string(a):
		r.fail("encrypt ok but wrapped is empty or equals the plaintext")
		return
	}
	encB, err := h.do(ctx, request{Action: "encrypt", Plaintext: b})
	switch {
	case err != nil:
		r.fail(err.Error())
		return
	case !encB.OK:
		r.fail(answerDetail("encrypt", encB))
		return
	case encB.Wrapped == "" || encB.Wrapped == string(b):
		r.fail("encrypt ok but wrapped is empty or equals the plaintext")
		return
	}
	// decrypt in the same order as encrypted: a plugin that stores and echoes
	// the last plaintext returns B for wrappedA and fails here
	decA, err := h.do(ctx, request{Action: "decrypt", Wrapped: encA.Wrapped})
	switch {
	case err != nil:
		r.fail(err.Error())
		return
	case !decA.OK:
		r.fail(answerDetail("decrypt", decA))
		return
	case !bytes.Equal(decA.Plaintext, a):
		r.fail("decrypt ok but plaintext differs from probe A (stateful echo?)")
		return
	}
	decB, err := h.do(ctx, request{Action: "decrypt", Wrapped: encB.Wrapped})
	switch {
	case err != nil:
		r.fail(err.Error())
		return
	case !decB.OK:
		r.fail(answerDetail("decrypt", decB))
		return
	case !bytes.Equal(decB.Plaintext, b):
		r.fail("decrypt ok but plaintext differs from probe B (NUL/high-byte mangling?)")
		return
	}
	r.ok(fmt.Sprintf("two distinct probes (0x%02x.. and 0x00..0xff) round trip exact", a[0]))
}

func runErrorShape(ctx context.Context, h *host, r *ConformanceResult) {
	dec, err := h.do(ctx, request{Action: "decrypt", Wrapped: bogusWrapped})
	switch {
	case err != nil:
		// a bogus blob must get an answer, never a transport failure
		r.fail(err.Error())
		return
	case dec.OK:
		// a wrapper format that "decrypts" a deliberately undecryptable blob
		// has no integrity
		r.fail("answered ok:true for a deliberately undecryptable blob")
		return
	case dec.Error == nil || dec.Error.Code == "" || dec.Error.Message == "":
		r.fail("ok:false without a complete error object (code and message)")
		return
	}
	r.ok(fmt.Sprintf("error object %s: %s", dec.Error.Code, dec.Error.Message))
}

func runRepeat(ctx context.Context, h *host, probe []byte, r *ConformanceResult) {
	if resp, err := h.do(ctx, request{Action: "encrypt", Plaintext: probe}); err != nil {
		r.fail(fmt.Sprintf("session reuse: %v", err))
		return
	} else if !resp.OK {
		r.fail(fmt.Sprintf("session reuse: %s", answerDetail("encrypt", resp)))
		return
	}
	h.kill() // force a death: the next request must respawn and still succeed
	if resp, err := h.do(ctx, request{Action: "encrypt", Plaintext: probe}); err != nil {
		r.fail(fmt.Sprintf("after respawn: %v", err))
		return
	} else if !resp.OK {
		r.fail(fmt.Sprintf("after respawn: %s", answerDetail("encrypt", resp)))
		return
	}
	r.ok("second encrypt on the live session and after a respawn both ok")
}

func answerDetail(action string, resp *response) string {
	if resp.Error != nil {
		return fmt.Sprintf("%s answered ok:false (%s: %s)", action, resp.Error.Code, resp.Error.Message)
	}
	return action + " answered ok:false without an error object"
}
