package cmd

import (
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"

	usercorn "github.com/lunixbochs/usercorn/go"
	"github.com/lunixbochs/usercorn/go/debug"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/ui"
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

type UsercornCmd struct {
	Config *models.Config

	SetupFlags    func() error
	SetupUsercorn func() error
	MakeUsercorn  func(exe string) (models.Usercorn, error)
	RunUsercorn   func() error
	Teardown      func()

	NoExe, NoArgs bool

	Usercorn models.Usercorn
	Flags    *flag.FlagSet
}

func NewUsercornCmd() *UsercornCmd {
	fs := flag.NewFlagSet("cli", flag.ExitOnError)
	cmd := &UsercornCmd{Flags: fs}
	cmd.MakeUsercorn = func(exe string) (models.Usercorn, error) {
		// check permissions
		if stat, err := os.Stat(exe); err != nil {
			return nil, err
		} else if stat.Mode().Perm()&0111 == 0 {
			return nil, errors.Errorf("%s: permission denied (no execute bit)\n", exe)
		}
		return usercorn.NewUsercorn(exe, cmd.Config)
	}
	return cmd
}

type stackTracer interface {
	StackTrace() errors.StackTrace
}

func (c *UsercornCmd) PrintError(err error) {
	// print an error, and a stacktrace if available
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 40))
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	if err, ok := err.(stackTracer); ok {
		// parse full path and method name for each stack frame
		var frames [][]string
		for _, f := range err.StackTrace() {
			fullpath := ""
			fileline := fmt.Sprintf("%s:%d", f, f)
			method := fmt.Sprintf("%n", f)

			frame := fmt.Sprintf("%+s", f)
			tmp := strings.SplitN(frame, "\n", 3)
			if len(tmp) == 2 {
				pathsplit := strings.Split(tmp[0], "/")
				method = pathsplit[len(pathsplit)-1]
				fullpath = strings.TrimSpace(tmp[1])
			}
			frames = append(frames, []string{fullpath, fileline, method})
			if method == "main.main" {
				break
			}
		}
		// calculate column widths
		widths := make([]int, len(frames))
		for _, f := range frames {
			for i, s := range f {
				if len(s) > widths[i] {
					widths[i] = len(s)
				}
			}
		}
		// print pretty stacktrace
		for _, f := range frames {
			method := f[2]
			for i := 0; i < 2; i++ {
				if widths[i] > 0 {
					pad := strings.Repeat(" ", widths[i]-len(f[i]))
					fmt.Fprintf(os.Stderr, "%s%s | ", f[i], pad)
				}
			}
			fmt.Fprintf(os.Stderr, "%s()\n", method)
		}
	}
}

func (c *UsercornCmd) Run(argv, env []string) int {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fs := c.Flags
	// tracing flags
	trace := fs.Bool("trace", false, "recommended tracing options: -loop 8 -strace -mtrace2 -etrace -rtrace -ftrace")
	strace := fs.Bool("strace", false, "trace syscalls")
	mtrace := fs.Bool("mtrace", false, "trace memory access (single)")
	mtrace2 := fs.Bool("mtrace2", false, "trace memory access (batched)")
	btrace := fs.Bool("btrace", false, "trace basic blocks")
	etrace := fs.Bool("etrace", false, "trace execution")
	rtrace := fs.Bool("rtrace", false, "trace register modification")
	ftrace := fs.Bool("ftrace", false, "trace source file:line")
	tracefile := fs.String("to", "", "binary trace output file")

	rewind := fs.Bool("rewind", false, "enable CPU rewind")

	match := fs.String("match", "", "trace from specific function(s) (func[,func...][+depth])")
	looproll := fs.Int("loop", 0, "collapse loop blocks of this depth")
	demangle := fs.Bool("demangle", false, "demangle symbols using c++filt")
	symfile := fs.Bool("symfile", false, "display symbols as sym@<mapped file>")
	disbytes := fs.Bool("disbytes", false, "show instruction bytes with disassembly")
	strsize := fs.Int("strsize", 30, "limited -strace'd strings to length (0 disables)")
	var src strslice
	fs.Var(&src, "src", "append source directory to search for -ftrace")
	// used for Usage grouping
	tnames := []string{
		"trace", "strace", "mtrace", "mtrace2", "btrace", "etrace", "rtrace", "ftrace",
		"match", "loop", "demangle", "symfile", "disbytes", "strsize", "to",
	}

	inscount := fs.Bool("inscount", false, "print instruction count after execution")
	verbose := fs.Bool("v", false, "verbose output")
	prefix := fs.String("prefix", "", "library load prefix")
	base := fs.Uint64("base", 0, "force executable base address")
	ibase := fs.Uint64("ibase", 0, "force interpreter base address")
	skipinterp := fs.Bool("nointerp", false, "don't load binary's interpreter")
	native := fs.Bool("native", false, "[stub] use native syscall override (only works if host/guest arch/ABI matches)")
	stubsys := fs.Bool("stubsys", false, "stub missing syscalls")

	outfile := fs.String("o", "", "redirect debugging output to file (default stderr)")

	gdb := fs.Int("gdb", -1, "listen for gdb connection on localhost:<port>")

	streamui := fs.Bool("ui", false, "streaming text ui")
	tui := fs.Bool("tui", false, "experimental interactive text UI")
	startrepl := fs.Bool("repl", false, "experimental luaish repl")
	var exec strslice
	fs.Var(&exec, "ex", "execute luaish script(s) before starting")

	cpuprofile := fs.String("cpuprofile", "", "write cpu profile to <file>")
	memprofile := fs.String("memprofile", "", "write mem profile to <file>")

	var envSet strslice
	var envUnset strslice
	fs.Var(&envSet, "set", "set environment var in the form name=value")
	fs.Var(&envUnset, "unset", "unset environment variable, '-' to unset all")

	fs.Usage = func() {
		usage := "Usage: %s [options]"
		if !c.NoExe {
			usage += " <exe>"
		}
		if !c.NoExe || !c.NoArgs {
			usage += " [args...]"
		}
		usage += "\n\nOptions:\n"
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		var flags []*flag.Flag
		var tflags []*flag.Flag
		fs.VisitAll(func(f *flag.Flag) {
			for _, name := range tnames {
				if name == f.Name {
					tflags = append(tflags, f)
					return
				}
			}
			flags = append(flags, f)
		})
		models.PrintFlags(flags)
		fmt.Fprintf(os.Stderr, "\nTrace Options:\n")
		models.PrintFlags(tflags)
		fmt.Fprintf(os.Stderr, "\nExample:\n  %s -trace -symfile bins/x86_64.linux.elf\n", os.Args[0])
	}
	if c.SetupFlags != nil {
		if err := c.SetupFlags(); err != nil {
			panic(err)
		}
	}
	fs.Parse(argv[1:])

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(f)
	}
	var args []string
	if !c.NoExe {
		// make sure we were passed an executable
		args = fs.Args()
		if len(args) < 1 {
			fs.Usage()
			return 1
		}
	} else {
		args = []string{""}
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
	// implied flags
	if *looproll == 0 && *trace {
		*looproll = 8
	}
	if *tracefile == "" && !*tui && *trace && !*streamui {
		*trace = true
		*streamui = true
	}
	if *startrepl || *tui {
		*trace = true
		*rewind = true
	}
	if *rewind {
		*trace = true
	}
	if *verbose && !*streamui && !*tui {
		*streamui = true
	}
	config := &models.Config{
		SymFile:      *symfile,
		StubSyscalls: *stubsys,

		Env:  env,
		Args: args,

		ForceBase:       *base,
		ForceInterpBase: *ibase,
		LoadPrefix:      absPrefix,
		NativeFallback:  *native,
		SkipInterp:      *skipinterp,
		Strsize:         *strsize,
		Verbose:         *verbose,

		Trace: models.TraceConfig{
			Tracefile:  *tracefile,
			Everything: *trace,

			Block: *btrace,
			Ins:   *etrace,
			Mem:   *mtrace,
			Reg:   *rtrace,
			Sys:   *strace,

			// Filters
			LoopCollapse: *looproll,
			MemBatch:     *mtrace2 || *trace,
		},
		Rewind: *rewind,
		UI:     *streamui,

		// FIXME: these are UI tracing flags and now broken
		Demangle:    *demangle,
		DisBytes:    *disbytes,
		InsCount:    *inscount,
		SourcePaths: src,
		TraceSource: *ftrace || *trace,
	}
	c.Config = config
	// FIXME: TraceMatch* is broken by trace changes
	if *match != "" {
		split := strings.SplitN(*match, "+", 2)
		if len(split) > 1 {
			if split[1] == "" {
				config.Trace.MatchDepth = 999999
			} else {
				config.Trace.MatchDepth, _ = strconv.Atoi(split[1])
			}
		}
		config.Trace.Match = strings.Split(split[0], ",")
	}

	if *outfile != "" {
		out, err := os.OpenFile(*outfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			panic(err)
		}
		config.Output = out
	}

	// merge environment with flags
	envSkip := make(map[string]bool)
	for _, v := range envSet {
		if strings.Contains(v, "=") {
			split := strings.SplitN(v, "=", 2)
			envSkip[split[0]] = true
		} else {
			fmt.Fprintf(os.Stderr, "warning: skipping invalid env set %#v\n", v)
		}
	}
	// unset specified env vars
	for _, v := range envUnset {
		if v == "-" {
			env = nil
			break
		}
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
	config.Env = envSet

	corn, err := c.MakeUsercorn(args[0])
	if err != nil {
		c.PrintError(err)
		return 1
	}
	c.Usercorn = corn
	if c.SetupUsercorn != nil {
		if err := c.SetupUsercorn(); err != nil {
			c.PrintError(err)
			return 1
		}
	}
	teardown := func() {
		if *cpuprofile != "" {
			pprof.StopCPUProfile()
		}
		if *memprofile != "" {
			f, err := os.Create(*memprofile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not write heap profile: %s\n", err)
			}
			pprof.WriteHeapProfile(f)
		}
		if c.Teardown != nil {
			c.Teardown()
		}
	}
	defer teardown()

	// start gdb server
	if *gdb > 0 {
		conn, err := debug.Accept("localhost", strconv.Itoa(*gdb))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error accepting conn on port %d: %v\n", *gdb, err)
			return 1
		}
		go debug.NewGdbstub(corn).Run(conn)
	}

	if *tui {
		tui, err := ui.NewTui(corn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error starting tui: %v\n", err)
			return 1
		}
		corn.Gate().Lock()
		defer tui.Close()
		tui.Run()
	} else if *startrepl || len(exec) > 0 {
		repl, err := ui.NewRepl(corn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error starting repl: %v\n", err)
			return 1
		}
		for _, script := range exec {
			text, err := ioutil.ReadFile(script)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading script %s: %v\n", script, err)
				return 1
			}
			lines := strings.Split(string(text), "\n")
			if repl.Lua.Exec(lines) {
				fmt.Fprintf(os.Stderr, "unexpected EOF in script %s\n", script)
				return 1
			}
		}
		if *startrepl {
			corn.Gate().Lock()
			defer repl.Close()
			repl.Run()
		}
	}
	// start executable
	if c.RunUsercorn != nil {
		err = c.RunUsercorn()
	} else {
		err = corn.Run()
	}
	if err != nil {
		if e, ok := err.(models.ExitStatus); ok {
			return int(e)
		} else {
			c.PrintError(err)
			return 1
		}
	}
	return 0
}
