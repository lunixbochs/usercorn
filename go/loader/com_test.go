package loader

import (
	"testing"
)

const comFile = "../../bins/simple.com"

func TestComLoad(t *testing.T) {
	_, err := NewComLoader(comFile)
	if err != nil {
		t.Fatal(err)
	}
}

func TestComSegments(t *testing.T) {
	elf, err := NewComLoader(comFile)
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
