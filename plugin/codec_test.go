package plugin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadLineHappy(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("{\"id\":1}\nnext\n"))
	line, err := readLine(r, 1024)
	require.NoError(t, err)
	assert.Equal(t, "{\"id\":1}", string(line))
}

func TestReadLineRejectsCR(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("{\"id\":1}\r\n"))
	_, err := readLine(r, 1024)
	require.Error(t, err)
	assert.ErrorIs(t, err, errCRInLine)
}

func TestReadLineRejectsBlank(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("   \n"))
	_, err := readLine(r, 1024)
	require.Error(t, err)
	assert.ErrorIs(t, err, errBlankLine)
}

func TestReadLineEnforcesCap(t *testing.T) {
	in := strings.Repeat("a", 2048) + "\n"
	r := bufio.NewReader(strings.NewReader(in))
	_, err := readLine(r, 1024)
	require.Error(t, err)
	assert.ErrorIs(t, err, errLineTooLong)
}

func TestReadLineRejectsPartialThenEOF(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("{\"id\":1"))
	_, err := readLine(r, 1024)
	require.Error(t, err)
	assert.ErrorIs(t, err, errPartialLine)
}

func TestReadLineCleanEOF(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(""))
	_, err := readLine(r, 1024)
	assert.ErrorIs(t, err, io.EOF)
}

func TestReadLineRejectsInvalidUTF8(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{'a', 0xff, 0xfe, '\n'}))
	_, err := readLine(r, 1024)
	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidUTF8)
}

func TestReadLineSpansBufioBuffer(t *testing.T) {
	// A line longer than bufio's 4096 default buffer must still read whole.
	long := "{\"id\":1,\"blob\":\"" + strings.Repeat("x", 8192) + "\"}\n"
	r := bufio.NewReader(strings.NewReader(long))
	line, err := readLine(r, 1<<20)
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSuffix(long, "\n"), string(line))
}

func TestWriteLineAppendsLF(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeLine(&buf, request{ID: 1, Action: "encrypt"}))
	out := buf.String()
	assert.True(t, strings.HasSuffix(out, "}\n"), "must end with LF, got %q", out)
	assert.NotContains(t, out, "\r")
}

func TestDecodeIntoRejectsNonJSON(t *testing.T) {
	var r response
	err := decodeInto([]byte("not json"), &r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-JSON stdout")
}

func TestHandshakeTagsPinned(t *testing.T) {
	b, err := json.Marshal(handshakeOut{Protocol: "sops-plugin", MaxVersion: 1})
	require.NoError(t, err)
	assert.JSONEq(t, `{"protocol":"sops-plugin","max_version":1}`, string(b))

	var in handshakeIn
	require.NoError(t, json.Unmarshal([]byte(`{"protocol":"sops-plugin","version":1,"plugin":"p","plugin_version":"1.0.0"}`), &in))
	assert.Equal(t, "sops-plugin", in.Protocol)
	assert.Equal(t, 1, in.Version)
	assert.Equal(t, "p", in.Plugin)
	assert.Equal(t, "1.0.0", in.PluginVersion)
}
