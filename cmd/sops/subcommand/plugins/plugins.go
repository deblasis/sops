// Package plugins implements the `sops plugins` subcommand: PATH discovery
// diagnostics (list) and third-party self-certification (verify).
package plugins

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/getsops/sops/v3/plugin"
)

const namePrefix = "sops-plugin-"

// List scans PATH for sops-plugin-* executables and prints one
// name<TAB>version-summary<TAB>path line per plugin. Read-only: no allowlist
// is consulted, the probe only reads a handshake.
func List(w io.Writer) error {
	seen := map[string]bool{}
	var names []string
	byName := map[string]string{}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // unreadable PATH entries are the normal case, not an error
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasPrefix(e.Name(), namePrefix) {
				continue
			}
			if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(e.Name()), ".exe") {
				continue // same rule as resolution: native executables only
			}
			base := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
			key := base
			if runtime.GOOS == "windows" {
				key = strings.ToLower(base) // PATH lookup is case-insensitive
			}
			if seen[key] {
				continue // first PATH hit wins, mirroring resolution order
			}
			seen[key] = true
			abs, err := filepath.Abs(filepath.Join(dir, e.Name()))
			if err != nil {
				abs = filepath.Join(dir, e.Name())
			}
			names = append(names, key)
			byName[key] = fmt.Sprintf("%s\t%s\t%s", base, plugin.NewProbe(abs).VersionSummary(), abs)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintln(w, byName[n])
	}
	return nil
}

// Verify runs positive conformance checks against an explicitly named plugin
// binary and prints one PASS/FAIL line per check. A non-nil return means at
// least one check failed; the caller maps it to a non-zero exit code.
func Verify(w io.Writer, binaryPath string) error {
	abs, err := filepath.Abs(binaryPath)
	if err != nil {
		return fmt.Errorf("resolving %q to an absolute path: %w", binaryPath, err)
	}
	if !plugin.CheckExecutable(abs) {
		return fmt.Errorf("%s is not a native executable; plugins must be executables (on Windows, .exe)", abs)
	}
	failed := false
	for _, r := range plugin.RunConformance(abs) {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
			failed = true
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", status, r.Name, r.Detail)
	}
	if failed {
		return errors.New("plugin conformance failed")
	}
	return nil
}
