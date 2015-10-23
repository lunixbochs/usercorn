package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/lunixbochs/usercorn/go/models"
)

func main() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fs := flag.NewFlagSet("cli", flag.ExitOnError)
	verbose := fs.Bool("v", false, "verbose output")
	trace := fs.Bool("trace", false, "recommended tracing options: -loop 8 -strace -mtrace2 -etrace -rtrace")
	strace := fs.Bool("strace", false, "trace syscalls")
	mtrace := fs.Bool("mtrace", false, "trace memory access (single)")
	mtrace2 := fs.Bool("mtrace2", false, "trace memory access (batched)")
	etrace := fs.Bool("etrace", false, "trace execution")
	rtrace := fs.Bool("rtrace", false, "trace register modification")
	looproll := fs.Int("loop", 0, "collapse loop blocks of this depth")
	prefix := fs.String("prefix", "", "library load prefix")
	base := fs.Uint64("base", 0, "force executable base address")
	ibase := fs.Uint64("ibase", 0, "force interpreter base address")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <exe> [args...]\n", os.Args[0])
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])
	args := fs.Args()
	if len(args) < 1 {
		fs.Usage()
		os.Exit(1)
	}
	absPrefix := ""
	var err error
	if *prefix != "" {
		absPrefix, err = filepath.Abs(*prefix)
		if err != nil {
			log.Fatal(err)
		}
	}
	corn, err := NewUsercorn(args[0], absPrefix)
	if err != nil {
		log.Fatal(err)
	}
	corn.Verbose = *verbose
	corn.TraceSys = *strace || *trace
	corn.TraceMem = *mtrace
	corn.TraceMemBatch = *mtrace2 || *trace
	corn.TraceReg = *rtrace || *trace
	corn.TraceExec = *etrace || *trace
	if *looproll == 0 && *trace {
		*looproll = 8
	}
	corn.LoopCollapse = *looproll
	corn.ForceBase = *base
	corn.ForceInterpBase = *ibase

	err = corn.Run(args, os.Environ())
	if err != nil {
		if e, ok := err.(models.ExitStatus); ok {
			os.Exit(int(e))
		} else {
			log.Fatal(err)
		}
	}
}
