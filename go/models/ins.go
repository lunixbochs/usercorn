package models

type Ins interface {
	Addr() uint64
	Bytes() []byte
	Mnemonic() string
	OpStr() string
}
