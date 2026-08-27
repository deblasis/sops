package plugin

import (
	"bufio"
	"bytes"
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

// max includes the LF: a max-1 payload + LF is the largest accepted line.
func TestReadLineCapBoundary(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(strings.Repeat("a", 1023) + "\n"))
	line, err := readLine(r, 1024)
	require.NoError(t, err)
	assert.Equal(t, 1023, len(line))

	r = bufio.NewReader(strings.NewReader(strings.Repeat("a", 1024) + "\n"))
	_, err = readLine(r, 1024)
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

func TestReadLineCapEnforcedAcrossBufferFull(t *testing.T) {
	// Oversized line rejected mid-accumulation, not after buffering it all.
	in := strings.Repeat("a", 8192) + "\n"
	r := bufio.NewReader(strings.NewReader(in))
	_, err := readLine(r, 4096)
	require.Error(t, err)
	assert.ErrorIs(t, err, errLineTooLong)
}

func TestReadLineRejectsCRMidLine(t *testing.T) {
	// CR is banned anywhere in a line, not just as CRLF framing.
	r := bufio.NewReader(strings.NewReader("a\rb\n"))
	_, err := readLine(r, 1024)
	require.Error(t, err)
	assert.ErrorIs(t, err, errCRInLine)
}

// NUL is valid UTF-8: framing accepts it, only JSON decoding rejects it.
func TestReadLineAcceptsNULButDecodeRejects(t *testing.T) {
	line := []byte{'a', 0x00, 'b'}
	r := bufio.NewReader(bytes.NewReader(append(line, '\n')))
	got, err := readLine(r, 1024)
	require.NoError(t, err)
	assert.Equal(t, line, got)

	var resp response
	require.Error(t, decodeInto(got, &resp))
}

func TestWriteLineAppendsLF(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeLine(&buf, request{ID: 1, Action: "encrypt"}))
	out := buf.String()
	assert.True(t, strings.HasSuffix(out, "}\n"), "must end with LF, got %q", out)
	assert.NotContains(t, out, "\r")
}

type shortWriter struct{}

// Writes succeed but swallow bytes: must surface as io.ErrShortWrite.
func (shortWriter) Write(b []byte) (int, error) { return len(b) / 2, nil }

func TestWriteLineRejectsShortWrite(t *testing.T) {
	assert.ErrorIs(t, writeLine(shortWriter{}, request{ID: 1, Action: "encrypt"}), io.ErrShortWrite)
}

func TestDecodeIntoRejectsNonJSON(t *testing.T) {
	var r response
	err := decodeInto([]byte("not json"), &r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-JSON stdout")
}
