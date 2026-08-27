// Command testplugin is the conformance dummy for the sops-plugin/1 suite.
// SOPS_TESTPLUGIN_MODE selects misbehavior; default is a correct session plugin.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
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
	case "", "version_high", "garbage", "unsolicited", "wrongid", "oversized", "never", "authfail", "exit1_startup", "unflushed", "oneshot":
	default:
		// a typo must never silently become a healthy plugin
		fmt.Fprintf(os.Stderr, "unknown SOPS_TESTPLUGIN_MODE: %s\n", mode)
		os.Exit(2)
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

	nAnswered := 0
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
		case "unflushed":
			// write response without newline, then hang: host must time out, not accept
			b, _ := json.Marshal(resp{ID: r.ID, OK: true, Plaintext: r.Plaintext})
			os.Stdout.Write(b)
			for {
				time.Sleep(time.Hour)
			}
		}
		switch r.Action {
		case "encrypt":
			wrapped := "test.v1." + base64.StdEncoding.EncodeToString(r.Plaintext)
			writeJSON(out, resp{ID: r.ID, OK: true, Wrapped: wrapped, KeyRef: "testkey/primary"})
		case "decrypt":
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
