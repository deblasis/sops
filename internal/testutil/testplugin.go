// Package testutil holds test-only helpers shared across packages.
package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var (
	buildOnce sync.Once
	buildPath string
	buildErr  error
)

// BuildTestPlugin compiles the conformance dummy (internal/testplugin) once
// per test binary and returns its path. The binary is named
// sops-plugin-testplugin so PATH discovery finds it. No cleanup: the binary
// must outlive every test in the run.
func BuildTestPlugin(t testing.TB) string {
	t.Helper()
	buildOnce.Do(func() {
		// locate the repo root through this file so any calling package works
		_, thisFile, _, _ := runtime.Caller(0)
		root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
		src := filepath.Join(root, "internal", "testplugin")
		dir, err := os.MkdirTemp("", "sops-plugin-test")
		if err != nil {
			buildErr = err
			return
		}
		bin := filepath.Join(dir, "sops-plugin-testplugin")
		if runtime.GOOS == "windows" {
			bin += ".exe" // the plugin resolver accepts .exe only on windows
		}
		cmd := exec.Command("go", "build", "-o", bin, src)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			buildErr = fmt.Errorf("%v (go build -o %s %s)", err, bin, src)
			return
		}
		buildPath = bin
	})
	if buildErr != nil {
		t.Fatalf("building testplugin: %v", buildErr)
	}
	return buildPath
}
