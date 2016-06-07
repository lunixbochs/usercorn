package cmd

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

type UsercornCmd struct {
	Config *models.Config

	SetupFlags    func() error
	SetupUsercorn func() error
	MakeUsercorn  func(exe string) (models.Usercorn, error)
	RunUsercorn   func(args, env []string) error
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
			return nil, fmt.Errorf("%s: permission denied (no execute bit)\n", exe)
		}
		return usercorn.NewUsercorn(exe, cmd.Config)
	}
	return cmd
}

func (c *UsercornCmd) Run(argv, env []string) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fs := c.Flags
	verbose := fs.Bool("v", false, "verbose output")
	trace := fs.Bool("trace", false, "recommended tracing options: -loop 8 -strace -mtrace2 -etrace -rtrace")
	strace := fs.Bool("strace", false, "trace syscalls")
	mtrace := fs.Bool("mtrace", false, "trace memory access (single)")
	mtrace2 := fs.Bool("mtrace2", false, "trace memory access (batched)")
	btrace := fs.Bool("btrace", false, "trace basic blocks")
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
	native := fs.Bool("native", false, "[stub] use native syscall override (only works if host/guest arch/ABI matches)")

	outfile := fs.String("o", "", "redirect debugging output to file (default stderr)")

	savepre := fs.String("savepre", "", "save state to file and exit before emulation starts")
	savepost := fs.String("savepost", "", "save state to file after emulation ends")

	listen := fs.Int("listen", -1, "listen for debug connection on localhost:<port>")
	connect := fs.Int("connect", -1, "connect to remote usercorn debugger on localhost:<port>")

	var envSet strslice
	var envUnset strslice
	fs.Var(&envSet, "set", "set environment var in the form name=value")
	fs.Var(&envUnset, "unset", "unset environment variable")

	fs.Usage = func() {
		usage := "Usage: %s [options]"
		if !c.NoExe {
			usage += " <exe>"
		}
		if !c.NoExe || !c.NoArgs {
			usage += " [args...]"
		}
		usage += "\n"
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		fmt.Fprintf(os.Stderr, "Debug Client: %s -connect <port>\n", os.Args[0])
		fs.PrintDefaults()
	}
	if c.SetupFlags != nil {
		if err := c.SetupFlags(); err != nil {
			panic(err)
		}
	}
	fs.Parse(argv[1:])

	// connect to debug server (skips rest of usercorn)
	if *connect > 0 {
		addr := net.JoinHostPort("localhost", strconv.Itoa(*connect))
		if err := debug.RunClient(addr); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}

	var args []string
	if !c.NoExe {
		// make sure we were passed an executable
		args = fs.Args()
		if len(args) < 1 {
			fs.Usage()
			os.Exit(1)
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
	if *looproll == 0 && *trace {
		*looproll = 8
	}
	config := &models.Config{
		Demangle:        *demangle,
		ForceBase:       *base,
		ForceInterpBase: *ibase,
		LoadPrefix:      absPrefix,
		LoopCollapse:    *looproll,
		NativeFallback:  *native,
		SavePost:        *savepost,
		SavePre:         *savepre,
		SkipInterp:      *skipinterp,
		Strsize:         *strsize,
		TraceBlock:      *btrace,
		TraceExec:       *etrace || *trace,
		TraceMem:        *mtrace,
		TraceMemBatch:   *mtrace2 || *trace,
		TraceReg:        *rtrace || *trace,
		TraceSys:        *strace || *trace,
		Verbose:         *verbose,
	}
	c.Config = config
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

	corn, err := c.MakeUsercorn(args[0])
	if err != nil {
		panic(err)
	}
	c.Usercorn = corn
	if c.SetupUsercorn != nil {
		if err := c.SetupUsercorn(); err != nil {
			panic(err)
		}
	}
	if c.Teardown != nil {
		// won't run on os.Exit(), so it's manually run below
		defer c.Teardown()
	}

	// start debug server
	if *listen > 0 {
		debugger := debug.NewDebugger(corn)
		addr := net.JoinHostPort("localhost", strconv.Itoa(*listen))
		if err = debugger.Listen(addr); err != nil {
			fmt.Fprintf(os.Stderr, "error listening on port %d: %v\n", *listen, err)
			if c.Teardown != nil {
				c.Teardown()
			}
			os.Exit(1)
		}
	}

	// start executable
	if c.RunUsercorn != nil {
		err = c.RunUsercorn(args, env)
	} else {
		err = corn.Run(args, env)
	}
	if err != nil {
		if e, ok := err.(models.ExitStatus); ok {
			if c.Teardown != nil {
				c.Teardown()
			}
			os.Exit(int(e))
		} else {
			panic(err)
		}
	}
}
