package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type partialWriteConn struct {
	writes []int
	buffer bytes.Buffer
}

func (c *partialWriteConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *partialWriteConn) Close() error                       { return nil }
func (c *partialWriteConn) LocalAddr() net.Addr                { return nil }
func (c *partialWriteConn) RemoteAddr() net.Addr               { return nil }
func (c *partialWriteConn) SetDeadline(_ time.Time) error      { return nil }
func (c *partialWriteConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *partialWriteConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *partialWriteConn) Write(p []byte) (int, error) {
	if len(c.writes) == 0 {
		return 0, io.ErrShortWrite
	}

	n := c.writes[0]
	c.writes = c.writes[1:]
	if n > len(p) {
		n = len(p)
	}
	_, _ = c.buffer.Write(p[:n])
	return n, nil
}

func TestWriteAllHandlesPartialWrites(t *testing.T) {
	conn := &partialWriteConn{writes: []int{2, 3, 4}}
	payload := []byte("benchmark")

	if err := writeAll(conn, payload); err != nil {
		t.Fatalf("writeAll returned error: %v", err)
	}

	if got := conn.buffer.String(); got != string(payload) {
		t.Fatalf("writeAll wrote %q, want %q", got, payload)
	}
}
