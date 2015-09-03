package loader

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"testing"
)

var cgcFile io.ReaderAt

func init() {
	p, err := ioutil.ReadFile("../../bins/x86.linux.cgc")
	if err != nil {
		log.Fatal(err)
	}
	cgcFile = bytes.NewReader(p)
}

func TestCgcLoad(t *testing.T) {
	_, err := NewCgcLoader(cgcFile)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCgcSegments(t *testing.T) {
	elf, err := NewCgcLoader(cgcFile)
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
