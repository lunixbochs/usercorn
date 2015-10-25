package loader

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"
)

var elfFile io.ReaderAt

func init() {
	p, err := ioutil.ReadFile("../../bins/x86.linux.elf")
	if err != nil {
		panic(err)
	}
	elfFile = bytes.NewReader(p)
}

func TestElfLoad(t *testing.T) {
	_, err := NewElfLoader(elfFile)
	if err != nil {
		t.Fatal(err)
	}
}

func TestElfSymbol(t *testing.T) {
	elf, err := NewElfLoader(elfFile)
	if err != nil {
		t.Fatal(err)
	}
	_, err = elf.Symbols()
	if err != nil {
		t.Fatal(err)
	}
}

func TestElfSegments(t *testing.T) {
	elf, err := NewElfLoader(elfFile)
	if err != nil {
		t.Fatal(err)
	}
	segments, err := elf.Segments()
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) == 0 {
		t.Fatal("No segments found.")
	}
}
