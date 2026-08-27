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

	probe := make([]byte, probeLen)
	for i := range probe {
		probe[i] = byte(i + 1) // deterministic: a conformance probe is not a secret
	}

	runRoundTrip(ctx, h, probe, &res[1])
	runErrorShape(ctx, h, &res[2])
	runRepeat(ctx, h, probe, &res[3])
	return res
}

func runRoundTrip(ctx context.Context, h *host, probe []byte, r *ConformanceResult) {
	enc, err := h.do(ctx, request{Action: "encrypt", Plaintext: probe})
	switch {
	case err != nil:
		r.fail(err.Error())
		return
	case !enc.OK:
		r.fail(answerDetail("encrypt", enc))
		return
	case enc.Wrapped == "" || enc.Wrapped == string(probe):
		r.fail("encrypt ok but wrapped is empty or equals the plaintext")
		return
	}
	dec, err := h.do(ctx, request{Action: "decrypt", Wrapped: enc.Wrapped})
	switch {
	case err != nil:
		r.fail(err.Error())
		return
	case !dec.OK:
		r.fail(answerDetail("decrypt", dec))
		return
	case !bytes.Equal(dec.Plaintext, probe):
		r.fail("decrypt ok but plaintext differs from the probe key")
		return
	}
	r.ok(fmt.Sprintf("%d-byte key wrapped to %d bytes, round trip exact", len(probe), len(enc.Wrapped)))
}

func runErrorShape(ctx context.Context, h *host, r *ConformanceResult) {
	dec, err := h.do(ctx, request{Action: "decrypt", Wrapped: bogusWrapped})
	switch {
	case err != nil:
		// a bogus blob must get an answer, never a transport failure
		r.fail(err.Error())
		return
	case dec.OK:
		r.ok("answered ok:true for a bogus blob (implausible but allowed)")
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
	h.kill() // simulate a clean exit: the next request must tolerate a respawn
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
