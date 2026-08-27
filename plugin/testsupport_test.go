package plugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var (
	testPluginOnce sync.Once
	testPluginPath string
	testPluginErr  error
)

// named sops-plugin-testplugin so PATH discovery finds it
func buildTestPlugin(t *testing.T) string {
	t.Helper()
	testPluginOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sops-plugin-test")
		if err != nil {
			testPluginErr = err
			return
		}
		bin := filepath.Join(dir, "sops-plugin-testplugin")
		if runtime.GOOS == "windows" {
			bin += ".exe" // our resolver accepts .exe only on windows
		}
		cmd := exec.Command("go", "build", "-o", bin, "../internal/testplugin")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			testPluginErr = err
			return
		}
		testPluginPath = bin
	})
	if testPluginErr != nil {
		t.Fatalf("building testplugin: %v", testPluginErr)
	}
	return testPluginPath
}

// put the plugin's dir first on PATH for discovery tests
func prependPath(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
