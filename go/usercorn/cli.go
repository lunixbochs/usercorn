package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	usercorn "github.com/lunixbochs/usercorn/go"
	"github.com/lunixbochs/usercorn/go/debug"
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

// like go io.Copy(), but returns a channel to notify you upon completion
func copyNotify(dst io.Writer, src io.Reader) chan int {
	ret := make(chan int)
	go func() {
		io.Copy(dst, src)
		ret <- 1
	}()
	return ret
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
	strsize := fs.Int("strsize", 30, "limited -strace'd strings to length (0 disables)")
	skipinterp := fs.Bool("nointerp", false, "don't load binary's interpreter")

	listen := fs.Int("listen", -1, "listen for debug connection on localhost:<port>")
	connect := fs.Int("connect", -1, "connect to remote usercorn debugger on localhost:<port>")

	var envSet strslice
	var envUnset strslice
	fs.Var(&envSet, "set", "set environment var in the form name=value")
	fs.Var(&envUnset, "unset", "unset environment variable")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <exe> [args...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Debug Client: %s -connect <port>\n", os.Args[0])
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])

	// connect to debug server (skips rest of usercorn)
	if *connect > 0 {
		addr := net.JoinHostPort("localhost", strconv.Itoa(*connect))
		if err := debug.RunClient(addr); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}

	// make sure we were passed an executable
	args := fs.Args()
	if len(args) < 1 {
		fs.Usage()
		os.Exit(1)
	}

	// build configuration
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
	config := &models.Config{
		Demangle:        *demangle,
		ForceBase:       *base,
		ForceInterpBase: *ibase,
		LoadPrefix:      absPrefix,
		LoopCollapse:    *looproll,
		SkipInterp:      *skipinterp,
		TraceExec:       *etrace || *trace,
		TraceMem:        *mtrace,
		TraceMemBatch:   *mtrace2 || *trace,
		TraceReg:        *rtrace || *trace,
		TraceSys:        *strace || *trace,
		Verbose:         *verbose,
		Strsize:         *strsize,
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

	// prep usercorn
	corn, err := usercorn.NewUsercorn(args[0], config)
	if err != nil {
		panic(err)
	}

	// start debug server
	if *listen > 0 {
		debugger := debug.NewDebugger(corn)
		addr := net.JoinHostPort("localhost", strconv.Itoa(*listen))
		if err = debugger.Listen(addr); err != nil {
			fmt.Fprintf(os.Stderr, "error listening on port %d: %v\n", *listen, err)
			return
		}
	}

	// start executable
	err = corn.Run(args, env)
	if err != nil {
		if e, ok := err.(models.ExitStatus); ok {
			os.Exit(int(e))
		} else {
			panic(err)
		}
	}
}
