package loader

import (
	"encoding/binary"
	"errors"

	"../models"
)

type LoaderHeader struct {
	arch      string
	bits      int
	byteOrder binary.ByteOrder
	os        string
	entry     uint64
	symCache  []models.Symbol
}

func (l *LoaderHeader) Arch() string {
	return l.arch
}

func (l *LoaderHeader) Bits() int {
	return l.bits
}

func (l *LoaderHeader) ByteOrder() binary.ByteOrder {
	if l.byteOrder == nil {
		return binary.LittleEndian
	}
	return l.byteOrder
}

func (l *LoaderHeader) OS() string {
	return l.os
}

func (l *LoaderHeader) Entry() uint64 {
	return l.entry
}

func (l *LoaderHeader) getSymbols() ([]models.Symbol, error) {
	return nil, errors.New("LoaderHeader.getSymbols() must be reimplemented by struct")
}

func (l *LoaderHeader) Symbols() ([]models.Symbol, error) {
	var err error
	if l.symCache == nil {
		l.symCache, err = l.getSymbols()
	}
	return l.symCache, err
}
