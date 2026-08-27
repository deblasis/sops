package plugin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

var (
	errCRInLine    = errors.New("plugin emitted CR inside a line (CRLF is a contract violation)")
	errBlankLine   = errors.New("plugin emitted a blank line")
	errLineTooLong = errors.New("line exceeds protocol cap")
	errPartialLine = errors.New("plugin output ended mid-line (EOF before LF)")
	errInvalidUTF8 = errors.New("plugin emitted invalid UTF-8")
)

// stdout is protocol only: one JSON object per LF-terminated line, ever.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var acc []byte
	for {
		chunk, err := r.ReadSlice('\n')
		acc = append(acc, chunk...)
		if len(acc) > max {
			return nil, errLineTooLong
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(acc) == 0 {
				return nil, io.EOF
			}
			return nil, errPartialLine
		}
		if err != nil {
			return nil, err
		}
		line := acc[:len(acc)-1]
		return line, validateLine(line)
	}
}

func validateLine(line []byte) error {
	// CR first: report CRLF violations as such even on whitespace-only lines.
	if bytes.ContainsRune(line, '\r') {
		return errCRInLine
	}
	if len(bytes.TrimSpace(line)) == 0 {
		return errBlankLine
	}
	if !utf8.Valid(line) {
		return errInvalidUTF8
	}
	return nil
}

func writeLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func decodeInto(line []byte, dst any) error {
	if err := json.Unmarshal(line, dst); err != nil {
		return fmt.Errorf("plugin emitted non-JSON stdout: %w", err)
	}
	return nil
}
