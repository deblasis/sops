package plugin

import (
	"fmt"
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

// every spawn passes gateExecution; tests must allowlist the test binary.
// bin is passed as a path override, so the exact path must be listed too.
func allowTestPlugin(t *testing.T, bin string) {
	t.Helper()
	writeLocalConfig(t, fmt.Sprintf("plugins:\n  allowed:\n    - testplugin\n    - %s\n", bin))
}
