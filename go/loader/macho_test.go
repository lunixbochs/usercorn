package loader

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"
)

var machoFile io.ReaderAt

func init() {
	p, err := ioutil.ReadFile("../../bins/x86.darwin.macho")
	if err != nil {
		panic(err)
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
	_, err = macho.Symbols()
	if err != nil {
		t.Fatal(err)
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
