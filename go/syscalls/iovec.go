package syscalls

type Iovec32 struct {
	Base uint32
	Len  uint32
}

type Iovec64 struct {
	Base uint64
	Len  uint64
}
