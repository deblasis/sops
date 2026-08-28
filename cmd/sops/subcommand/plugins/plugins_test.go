package plugins

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/getsops/sops/v3/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// executability is extension on Windows and exec bits elsewhere; arbitrary
// bytes are enough, the probe just reports them unreachable
func writeFakePlugin(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("not a real binary"), 0o755))
	return path
}

func pluginName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func TestListsExecutablePluginsSorted(t *testing.T) {
	dir := t.TempDir()
	writeFakePlugin(t, dir, pluginName("sops-plugin-beta"))
	writeFakePlugin(t, dir, pluginName("sops-plugin-alpha"))
	t.Setenv("PATH", dir)

	var buf bytes.Buffer
	require.NoError(t, List(&buf))
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "sops-plugin-alpha\t")
	assert.Contains(t, lines[0], filepath.Join(dir, pluginName("sops-plugin-alpha")))
	assert.Contains(t, lines[1], "sops-plugin-beta\t")
}

func TestListSkipsRelativePathEntries(t *testing.T) {
	// a "." PATH entry must not discover plugins from the current directory
	dir := t.TempDir()
	writeFakePlugin(t, dir, pluginName("sops-plugin-cwdplant"))
	t.Chdir(dir)
	t.Setenv("PATH", ".")

	var buf bytes.Buffer
	require.NoError(t, List(&buf))
	assert.Empty(t, buf.String())
}

func TestNonExecutableShadowDoesNotSuppressLaterExecutable(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	if runtime.GOOS == "windows" {
		// a non-.exe file in dirA: extension check alone must skip it
		require.NoError(t, os.WriteFile(filepath.Join(dirA, "sops-plugin-shadow.txt"), []byte("decoy"), 0o644))
	} else {
		// extensionless file without exec bits in dirA
		require.NoError(t, os.WriteFile(filepath.Join(dirA, "sops-plugin-shadow"), []byte("decoy"), 0o644))
	}
	real := writeFakePlugin(t, dirB, pluginName("sops-plugin-shadow"))
	t.Setenv("PATH", dirA+string(os.PathListSeparator)+dirB)

	var buf bytes.Buffer
	require.NoError(t, List(&buf))
	assert.Contains(t, buf.String(), real)
	assert.Equal(t, 1, strings.Count(buf.String(), "sops-plugin-shadow\t"),
		"shadow must be listed exactly once, from the executable dirB hit")
}

// verify accepts the same bare name a config uses: it resolves through PATH
// (prefix optional), not just as a filesystem path. The real testplugin
// binary proves the whole conformance run works off the resolved name.
func TestVerifyAcceptsBareName(t *testing.T) {
	bin := testutil.BuildTestPlugin(t)
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))

	var buf bytes.Buffer
	require.NoError(t, Verify(&buf, "testplugin", ""))
	assert.Contains(t, buf.String(), "PASS\thandshake")
	assert.Equal(t, 0, strings.Count(buf.String(), "FAIL"))

	// the prefixed form resolves too
	buf.Reset()
	require.NoError(t, Verify(&buf, "sops-plugin-testplugin", ""))
	assert.Contains(t, buf.String(), "PASS\thandshake")

	// an unknown name fails with resolution, not conformance
	err := Verify(&buf, "no-such-plugin", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not resolve as a plugin name")
}
