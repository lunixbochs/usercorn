package loader

import (
	"bytes"
	"testing"
)

func TestLoad(t *testing.T) {
	if _, err := LoadFile("../../bins/x86.linux.elf"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile("../../bins/x86.linux.cgc"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile("../../bins/x86.darwin.macho"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bytes.NewReader([]byte(""))); err == nil {
		t.Fatal("Failed to error on loading bad file.")
	}
}
