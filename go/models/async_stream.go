package models

import (
	"github.com/pkg/errors"
	"io"
	"time"
)

type AsyncStream struct {
	io.WriteCloser
	closed bool
	move   chan io.WriteCloser
	close  chan chan int
	write  chan []byte

	buffer [][]byte
	count  uint64
}

func NewAsyncStream(w io.WriteCloser) io.WriteCloser {
	a := &AsyncStream{
		WriteCloser: w,
		closed:      false,
		move:        make(chan io.WriteCloser),
		close:       make(chan chan int),
		write:       make(chan []byte, 1000),
	}
	go a.run()
	return a
}

func (a *AsyncStream) flush() {
	for _, p := range a.buffer {
		if _, err := a.WriteCloser.Write(p); err != nil {
			a.closed = true
			break
		}
	}
	a.buffer = a.buffer[:0]
	a.count = 0
}

func (a *AsyncStream) run() {
	duration := 25 * time.Millisecond
	t := time.NewTimer(duration)
	timer := false
	for !a.closed {
		select {
		case <-t.C:
			a.flush()
			timer = false
		case p := <-a.write:
			a.buffer = append(a.buffer, p)
			a.count += uint64(len(p))
			if len(a.buffer) > 1000 || a.count > 64000 {
				a.flush()
			}
		case w := <-a.move:
			a.WriteCloser = w
		case tmp := <-a.close:
			a.flush()
			a.WriteCloser.Close()
			a.closed = true
			tmp <- 1
			break
		}
		if len(a.buffer) > 0 && !timer {
			timer = true
			t.Reset(duration)
		}
	}
	if !t.Stop() {
		<-t.C
	}
}

func (a *AsyncStream) Move(w io.WriteCloser) {
	a.move <- w
}

func (a *AsyncStream) Write(p []byte) (int, error) {
	if a.closed {
		return 0, errors.New("async stream is closed")
	}
	tmp := make([]byte, len(p))
	copy(tmp, p)
	a.write <- tmp
	return len(tmp), nil
}

func (a *AsyncStream) Close() error {
	if a.closed {
		return errors.New("async stream was already closed")
	} else {
		tmp := make(chan int)
		a.close <- tmp
		<-tmp
	}
	return nil
}
