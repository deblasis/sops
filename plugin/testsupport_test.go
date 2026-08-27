package plugin

import (
	"os"
	"testing"

	"github.com/getsops/sops/v3/internal/testutil"
)

// thin wrapper: the build logic lives in internal/testutil, shared with the
// keyservice tests and the e2e suite
func buildTestPlugin(t *testing.T) string {
	t.Helper()
	return testutil.BuildTestPlugin(t)
}

// put the plugin's dir first on PATH for discovery tests
func prependPath(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// every spawn passes gateExecution; tests must allowlist the test binary
func allowTestPlugin(t *testing.T) {
	t.Helper()
	writeLocalConfig(t, "plugins:\n  allowed:\n    - testplugin\n")
}
