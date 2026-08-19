package agent

import (
	"encoding/binary"
	"errors"
)

// errShortRead means the buffer ran out mid-field.
var errShortRead = errors.New("truncated SSH wire encoding")

// reader walks the SSH wire encoding (RFC 4251 §5) strictly: every field has to
// be fully present, and the caller is expected to check that the whole buffer
// was consumed. Classification depends on that strictness — a payload that
// merely starts like an auth blob must not be mistaken for one.
type reader struct {
	buf []byte
}

func (r *reader) empty() bool {
	return len(r.buf) == 0
}

func (r *reader) remaining() int {
	return len(r.buf)
}

// bytes reads n raw bytes.
func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 || len(r.buf) < n {
		return nil, errShortRead
	}

	out := r.buf[:n]
	r.buf = r.buf[n:]

	return out, nil
}

// byteValue reads a single byte.
func (r *reader) byteValue() (byte, error) {
	b, err := r.bytes(1)
	if err != nil {
		return 0, err
	}

	return b[0], nil
}

// boolValue reads an SSH boolean.
func (r *reader) boolValue() (bool, error) {
	b, err := r.byteValue()
	if err != nil {
		return false, err
	}

	return b != 0, nil
}

// uint32Value reads a uint32.
func (r *reader) uint32Value() (uint32, error) {
	b, err := r.bytes(4)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(b), nil
}

// stringValue reads a length-prefixed string.
func (r *reader) stringValue() ([]byte, error) {
	n, err := r.uint32Value()
	if err != nil {
		return nil, err
	}

	// Guard against a length that would overflow int on 32-bit builds before
	// handing it to bytes.
	if uint64(n) > uint64(len(r.buf)) {
		return nil, errShortRead
	}

	return r.bytes(int(n))
}

// text is stringValue for fields that are meant to be human readable.
func (r *reader) text() (string, error) {
	b, err := r.stringValue()
	if err != nil {
		return "", err
	}

	return string(b), nil
}
