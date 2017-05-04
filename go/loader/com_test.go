package loader

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"
)

var comFile io.ReaderAt

func init() {
	p, err := ioutil.ReadFile("../../bins/simple.com")
	if err != nil {
		panic(err)
	}
	comFile = bytes.NewReader(p)
}

func TestComLoad(t *testing.T) {
	_, err := NewComLoader(comFile, "any")
	if err != nil {
		t.Fatal(err)
	}
}

func TestComSegments(t *testing.T) {
	elf, err := NewComLoader(comFile, "any")
	if err != nil {
		t.Fatal(err)
	}
	segments, err := elf.Segments()
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) == 0 {
		t.Fatal("No segments!")
	}
}
