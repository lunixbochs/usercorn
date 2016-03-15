package models

type Config struct {
	Color           bool
	Demangle        bool
	ForceBase       uint64
	ForceInterpBase uint64
	LoadPrefix      string
	LoopCollapse    int
	TraceExec       bool
	TraceMatch      []string
	TraceMatchDepth int
	TraceMem        bool
	TraceMemBatch   bool
	TraceReg        bool
	TraceSys        bool
	Verbose         bool
	Strsize         int

	PrefixArgs []string
}
