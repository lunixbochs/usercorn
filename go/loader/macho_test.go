package loader

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"testing"
)

var machoFile io.ReaderAt

func init() {
	p, err := ioutil.ReadFile("../../bins/x86.darwin.macho")
	if err != nil {
		log.Fatal(err)
	}
	machoFile = bytes.NewReader(p)
}

func TestMachOLoad(t *testing.T) {
	_, err := NewMachOLoader(machoFile)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMachOSymbol(t *testing.T) {
	macho, err := NewMachOLoader(machoFile)
	if err != nil {
		t.Fatal(err)
	}
	name, err := macho.Symbolicate(macho.Entry())
	if err != nil {
		t.Fatal(err)
	}
	if name == "" {
		t.Fatal("macho.Symbolicate() failed")
	}
}

func TestMachOSegments(t *testing.T) {
	macho, err := NewMachOLoader(machoFile)
	if err != nil {
		t.Fatal(err)
	}
	segments, err := macho.Segments()
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) == 0 {
		t.Fatal("No segments found.")
	}
}
