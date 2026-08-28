package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var (
	errNotExecutableType = errors.New("plugin resolved to a non-executable file type; only native executables are allowed")
	errNotFound          = errors.New("plugin executable not found on PATH")
)

var binaryNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// repo content must never pick the executable: names are charset-checked,
// resolution is PATH-only (never cwd) and native executables only.
func validateBinaryName(name string) error {
	if !binaryNameRe.MatchString(name) {
		return fmt.Errorf("invalid plugin binary name %q: only [a-zA-Z0-9_-], 1-128 chars", name)
	}
	return nil
}

// ResolveName resolves a bare plugin name (prefix optional) through PATH,
// the same lookup a key operation uses; diagnostics may name a plugin the
// way a config does.
func ResolveName(pluginRef string) (string, error) {
	name := strings.TrimSuffix(pluginRef, ".exe")
	name = strings.TrimPrefix(name, "sops-plugin-")
	return resolvePlugin(name, "")
}

func resolvePlugin(binaryName, pathOverride string) (string, error) {
	if err := validateBinaryName(binaryName); err != nil {
		return "", err
	}
	if pathOverride != "" {
		// relative overrides would let a committed .sops.yaml ship an executable
		if !filepath.IsAbs(pathOverride) {
			return "", fmt.Errorf("plugin path override must be absolute, got %q", pathOverride)
		}
		p := filepath.Clean(pathOverride)
		if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(p), ".exe") {
			return "", fmt.Errorf("%w: %s", errNotExecutableType, p)
		}
		if !isExecutableFile(p) {
			return "", fmt.Errorf("plugin path override %q is not an executable file", p)
		}
		return p, nil
	}
	exe := "sops-plugin-" + binaryName
	if runtime.GOOS == "windows" {
		exe += ".exe" // PATHEXT deliberately ignored: no .cmd/.bat shadowing
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		// a relative entry (like ".") would resolve plugins from whatever
		// the current directory happens to be: the never-cwd promise holds
		if !filepath.IsAbs(dir) {
			continue
		}
		cand := filepath.Join(dir, exe)
		if isExecutableFile(cand) {
			abs, err := filepath.Abs(cand)
			if err != nil {
				return "", fmt.Errorf("resolving %s to absolute: %w", cand, err)
			}
			return abs, nil
		}
	}
	// report a script pretending to be the plugin instead of a bare not-found,
	// so users learn they must install a native executable
	if runtime.GOOS == "windows" {
		for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
			if dir == "" || !filepath.IsAbs(dir) {
				continue
			}
			for _, ext := range []string{".cmd", ".bat", ".ps1"} {
				cand := filepath.Join(dir, "sops-plugin-"+binaryName+ext)
				if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
					return "", fmt.Errorf("%w: found %s", errNotExecutableType, cand)
				}
			}
		}
	}
	return "", fmt.Errorf("%w: %s (install it on PATH or set path in the plugin config)", errNotFound, exe)
}

func isExecutableFile(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Ext(path), ".exe")
	}
	return fi.Mode().Perm()&0o111 != 0
}
