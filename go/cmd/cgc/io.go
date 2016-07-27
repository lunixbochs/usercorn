package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"sync"
)

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
}

func (w WriteLogger) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (w WriteLogger) Write(p []byte) (int, error) {
	if len(p) > 0 {
		s := string(p)
		if w.Hex {
			s = hex.EncodeToString(p)
		}
		log.Printf("%s: %s", w.Prefix, s)
	}
	return 0, nil
}

func (w WriteLogger) Close() error { return nil }
