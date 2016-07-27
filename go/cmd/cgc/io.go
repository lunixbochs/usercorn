package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"sync"
)

type NullIO struct{}

func (n *NullIO) Read(p []byte) (int, error)  { return 0, io.EOF }
func (n *NullIO) Write(p []byte) (int, error) { return 0, nil }

type BufPipe struct {
	b bytes.Buffer
	c sync.Cond
	l sync.Mutex
}

func NewBufPipe() *BufPipe {
	b := &BufPipe{}
	b.c = sync.Cond{L: &b.l}
	return b
}

func NewBufPipePair() (io.ReadWriter, io.ReadWriter) {
	a, b := NewBufPipe(), NewBufPipe()
	return ReadWriter{a, b}, ReadWriter{b, a}
}

func (b *BufPipe) Read(p []byte) (int, error) {
	b.c.L.Lock()
	defer b.c.L.Unlock()
	// block if empty
	for b.b.Len() == 0 {
		b.c.Wait()
	}
	return b.b.Read(p)
}

func (b *BufPipe) Write(p []byte) (int, error) {
	b.c.L.Lock()
	defer b.c.L.Unlock()
	defer b.c.Signal()
	return b.b.Write(p)
}

type ReadWriter struct {
	io.Reader
	io.Writer
}

type WriteLogger struct {
	Prefix string
	Hex    bool
	buf    bytes.Buffer
}

func (w *WriteLogger) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (w *WriteLogger) Write(p []byte) (int, error) {
	w.buf.Write(p)
	if bytes.Contains(w.buf.Bytes(), []byte("\n")) {
		lines := bytes.Split(w.buf.Bytes(), []byte("\n"))
		last := len(lines) - 1
		for _, line := range lines[:last] {
			s := string(line)
			if w.Hex {
				s = hex.EncodeToString(line)
			}
			log.Printf("%s: %s", w.Prefix, s)
		}
		w.buf.Reset()
		w.buf.Write(lines[last])
	}
	return 0, nil
}

func (w *WriteLogger) Close() error { return nil }
