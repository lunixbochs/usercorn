package models

import (
	"testing"
)

func MappedFileTest(t *testing.T) {
	syms := []Symbol{
		{Name: "test"},
		{Name: "test2"},
	}
	file := &MappedFile{Symbols: syms}
	if file.SymbolLookup("test2").Name != "test2" {
		t.Error("Symbol lookup failed.")
	}
}
