package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	usercorn "github.com/lunixbochs/usercorn/go"
	"github.com/lunixbochs/usercorn/go/models"
)

type strslice []string

func (s *strslice) String() string {
	return fmt.Sprintf("%v", *s)
}

func (s *strslice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

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
	match := fs.String("match", "", "trace from specific function(s) (func[,func...][+depth]")
	looproll := fs.Int("loop", 0, "collapse loop blocks of this depth")
	prefix := fs.String("prefix", "", "library load prefix")
	base := fs.Uint64("base", 0, "force executable base address")
	ibase := fs.Uint64("ibase", 0, "force interpreter base address")
	demangle := fs.Bool("demangle", false, "demangle symbols using c++filt")

	var envSet strslice
	var envUnset strslice
	fs.Var(&envSet, "set", "set environment var in the form name=value")
	fs.Var(&envUnset, "unset", "unset environment variable")

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
			panic(err)
		}
	}
	if *looproll == 0 && *trace {
		*looproll = 8
	}
	config := &usercorn.Config{
		Demangle:        *demangle,
		ForceBase:       *base,
		ForceInterpBase: *ibase,
		LoadPrefix:      absPrefix,
		LoopCollapse:    *looproll,
		TraceExec:       *etrace || *trace,
		TraceMem:        *mtrace,
		TraceMemBatch:   *mtrace2 || *trace,
		TraceReg:        *rtrace || *trace,
		TraceSys:        *strace || *trace,
		Verbose:         *verbose,
	}
	if *match != "" {
		split := strings.SplitN(*match, "+", 2)
		if len(split) > 1 {
			if split[1] == "" {
				config.TraceMatchDepth = 999999
			} else {
				config.TraceMatchDepth, _ = strconv.Atoi(split[1])
			}
		}
		config.TraceMatch = strings.Split(split[0], ",")
	}
	// merge environment with flags
	env := os.Environ()
	envSkip := make(map[string]bool)
	for _, v := range envSet {
		if strings.Contains(v, "=") {
			split := strings.SplitN(v, "=", 2)
			envSkip[split[0]] = true
		} else {
			fmt.Fprintf(os.Stderr, "warning: skipping invalid env set %#v\n", v)
		}
	}
	for _, v := range envUnset {
		envSkip[v] = true
	}
	for _, v := range env {
		if strings.Contains(v, "=") {
			split := strings.SplitN(v, "=", 2)
			if _, ok := envSkip[split[0]]; !ok {
				envSet = append(envSet, v)
			}
		}
	}
	env = envSet
	// launch usercorn
	corn, err := usercorn.NewUsercorn(args[0], config)
	if err != nil {
		panic(err)
	}
	err = corn.Run(args, env)
	if err != nil {
		if e, ok := err.(models.ExitStatus); ok {
			os.Exit(int(e))
		} else {
			panic(err)
		}
	}
}
