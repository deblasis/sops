// Command testplugin is the conformance dummy for the sops-plugin/1 suite.
// SOPS_TESTPLUGIN_MODE selects misbehavior; default is a correct session plugin.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type hsIn struct {
	Protocol   string `json:"protocol"`
	MaxVersion int    `json:"max_version"`
}
type hsOut struct {
	Protocol      string `json:"protocol"`
	Version       int    `json:"version"`
	Plugin        string `json:"plugin"`
	PluginVersion string `json:"plugin_version"`
}
type req struct {
	ID        int64          `json:"id"`
	Action    string         `json:"action"`
	Config    map[string]any `json:"config"`
	Plaintext []byte         `json:"plaintext"`
	Wrapped   string         `json:"wrapped"`
}
type resp struct {
	ID        int64  `json:"id"`
	OK        bool   `json:"ok"`
	Plaintext []byte `json:"plaintext,omitempty"`
	Wrapped   string `json:"wrapped,omitempty"`
	KeyRef    string `json:"key_ref,omitempty"`
}
type perr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type respErr struct {
	ID    int64 `json:"id"`
	OK    bool  `json:"ok"`
	Error *perr `json:"error"`
}

func main() {
	mode := os.Getenv("SOPS_TESTPLUGIN_MODE")
	switch mode {
	case "", "version_high", "garbage", "unsolicited", "wrongid", "oversized", "never", "authfail", "exit1_startup", "unflushed", "oneshot", "hang_startup", "echo", "requireconfig", "bare_false", "incomplete_err", "ok_with_err", "clean_exit_startup", "noread", "stderrnoise", "empty_ok", "exit_clean_before_response", "crash_after_request", "crash_before_request", "procid":
	default:
		// a typo must never silently become a healthy plugin
		fmt.Fprintf(os.Stderr, "unknown SOPS_TESTPLUGIN_MODE: %s\n", mode)
		os.Exit(2)
	}
	// procid needs a per-PROCESS identity that survives exits: each spawn is a
	// fresh process, so the only state it can read back is a counter file
	procNum := 0
	if f := os.Getenv("SOPS_TESTPLUGIN_PROCFILE"); f != "" {
		b, _ := os.ReadFile(f)
		n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		procNum = n + 1
		os.WriteFile(f, []byte(strconv.Itoa(procNum)), 0o600)
	}
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	line, err := in.ReadBytes('\n')
	if err != nil {
		os.Exit(2)
	}
	var h hsIn
	if err := json.Unmarshal(line, &h); err != nil {
		os.Exit(2)
	}
	switch mode {
	case "clean_exit_startup":
		// exit 0 before any handshake byte: respawnable, not a startup failure
		return
	case "hang_startup":
		// sleep before the handshake: exercises the host's handshake timeout
		for {
			time.Sleep(time.Hour)
		}
	case "exit1_startup":
		// fail before the handshake: the host's handshake read gets EOF;
		// exit code 2 is intentional (kubectl convention for auth/config failure)
		fmt.Fprintln(os.Stderr, "startup broke")
		os.Exit(2)
	case "version_high":
		writeJSON(out, hsOut{Protocol: "sops-plugin", Version: 99, Plugin: "testplugin", PluginVersion: "1.0.0"})
		return
	}
	writeJSON(out, hsOut{Protocol: "sops-plugin", Version: 1, Plugin: "testplugin", PluginVersion: "1.2.3"})
	if mode == "crash_before_request" {
		// never read stdin: the host's request write breaks against a child
		// that died without reading, exercising the write-side half of the
		// exit-status resend rule
		fmt.Fprintln(os.Stderr, "crashed on purpose")
		os.Exit(7)
	}
	if mode == "noread" {
		// handshake done, then never read stdin again: the host's request
		// write must hit its deadline, not block forever on a full pipe
		for {
			time.Sleep(time.Hour)
		}
	}

	nAnswered := 0
	var lastPlain []byte // echo mode only: the stateful-echo conformance bait
	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			return // stdin closed, exit clean
		}
		var r req
		if err := json.Unmarshal(line, &r); err != nil {
			os.Exit(1)
		}
		switch mode {
		case "garbage":
			fmt.Fprintln(out, "this is not json")
			out.Flush()
			os.Exit(1)
		case "unsolicited":
			writeJSON(out, resp{ID: 999, OK: true})
			mode = "" // then behave
			continue
		case "wrongid":
			writeJSON(out, resp{ID: r.ID + 100, OK: true, Wrapped: "x"})
			continue
		case "oversized":
			// raw 1MiB+64 NUL payload: the line itself busts the host's size cap
			fmt.Fprintf(out, "{\"pad\":\"%s\"}\n", make([]byte, 1024*1024+64))
			out.Flush()
			os.Exit(1)
		case "never":
			for {
				time.Sleep(time.Hour) // hang until killed; select{} trips the deadlock detector
			}
		case "authfail":
			writeJSON(out, respErr{ID: r.ID, OK: false, Error: &perr{Code: "auth_failed", Message: "denied"}})
			continue
		case "bare_false":
			// ok:false with no error object at all
			writeJSON(out, resp{ID: r.ID, OK: false})
			continue
		case "incomplete_err":
			// ok:false with an error object missing its message
			writeJSON(out, respErr{ID: r.ID, OK: false, Error: &perr{Code: "internal"}})
			continue
		case "ok_with_err":
			// ok:true carrying an error object anyway
			writeJSON(out, respErr{ID: r.ID, OK: true, Error: &perr{Code: "internal", Message: "should not be here"}})
			continue
		case "exit_clean_before_response":
			// read the request, answer nothing, exit 0: exercises the host's
			// clean-exit respawn path (bounded by the spawn cap)
			return
		case "crash_after_request":
			// read the full request, then die without answering: a resend
			// could double-apply a wrap that already happened
			fmt.Fprintln(os.Stderr, "crashed on purpose")
			os.Exit(7)
		case "empty_ok":
			// ok:true with no payload: exercises the host-side diagnoses that
			// must name the binary
			writeJSON(out, resp{ID: r.ID, OK: true})
			continue
		case "unflushed":
			// write response without newline, then hang: host must time out, not accept
			b, _ := json.Marshal(resp{ID: r.ID, OK: true, Plaintext: r.Plaintext})
			os.Stdout.Write(b)
			for {
				time.Sleep(time.Hour)
			}
		}
		if mode == "stderrnoise" {
			// healthy answers plus a per-request stderr warning the host must
			// surface exactly once per operation (process reuse must not
			// re-warn old lines)
			fmt.Fprintf(os.Stderr, "fake mode: handling %s\n", r.Action)
		}
		switch r.Action {
		case "encrypt":
			lastPlain = r.Plaintext
			if mode == "requireconfig" && len(r.Config) == 0 {
				// a config-requiring plugin answers config_error when sops
				// sends no config (the shape `plugins verify` must cover)
				writeJSON(out, respErr{ID: r.ID, OK: false, Error: &perr{Code: "config_error", Message: "config required"}})
				continue
			}
			if mode == "echo" {
				writeJSON(out, resp{ID: r.ID, OK: true, Wrapped: "echo.v1.stored", KeyRef: "echokey/stored"})
				nAnswered++
				continue
			}
			wrapped := "test.v1." + base64.StdEncoding.EncodeToString(r.Plaintext)
			keyRef := "testkey/primary"
			if mode == "procid" {
				// every answer in this process carries the same identity: the
				// reuse tests compare key refs to count live plugin processes
				keyRef = fmt.Sprintf("testkey/proc%d", procNum)
			}
			writeJSON(out, resp{ID: r.ID, OK: true, Wrapped: wrapped, KeyRef: keyRef})
		case "decrypt":
			if mode == "echo" {
				// answers the stored plaintext no matter which blob is asked for
				writeJSON(out, resp{ID: r.ID, OK: true, Plaintext: lastPlain})
				nAnswered++
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Wrapped, "test.v1."))
			if err == nil {
				writeJSON(out, resp{ID: r.ID, OK: true, Plaintext: raw})
			} else {
				// no continue: every answered request must reach the oneshot exit check below
				writeJSON(out, respErr{ID: r.ID, OK: false, Error: &perr{Code: "invalid_request", Message: "bad wrapped blob"}})
			}
		default:
			writeJSON(out, respErr{ID: r.ID, OK: false, Error: &perr{Code: "unsupported_action", Message: r.Action}})
		}
		nAnswered++
		if mode == "oneshot" && nAnswered >= 1 {
			return // clean exit(0): must not count against restart budget
		}
	}
}

func writeJSON(w *bufio.Writer, v any) {
	b, _ := json.Marshal(v)
	w.Write(b)
	w.WriteByte('\n')
	w.Flush()
}
