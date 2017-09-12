package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"os"

	"github.com/lunixbochs/usercorn/go/arch"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/trace"
	"github.com/lunixbochs/usercorn/go/ui"
)

func PrintJson(tf *trace.TraceReader) error {
	out, err := json.Marshal(&tf.Header)
	if err != nil {
		return errors.Wrap(err, "error printing header")
	}
	fmt.Printf("%s\n", out)
	for {
		op, err := tf.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return errors.Wrap(err, "error reading next trace operation")
		}
		out, _ := json.Marshal(op)
		fmt.Printf("%s\n", out)
	}
	return nil
}

func PrintPretty(tf *trace.TraceReader) error {
	arch, OS, err := arch.GetArch(tf.Header.Arch, tf.Header.OS)
	if err != nil {
		return errors.Wrap(err, "arch.GetArch() failed")
	}
	config := &models.Config{}
	config.Init()
	replay := trace.NewReplay(arch, OS, tf.Header.CodeOrder, nil)
	defer replay.Flush()
	stream := ui.NewStreamUI(config, replay)
	replay.Listen(stream.Feed)
	for {
		op, err := tf.Next()
		// TODO: DRY? could make TraceReader behave more like Scanner
		if err == io.EOF {
			break
		} else if err != nil {
			return errors.Wrap(err, "error reading next trace operation")
		}
		replay.Feed(op)
	}
	return nil
}

func main() {
	fs := flag.NewFlagSet("args", flag.ExitOnError)
	jsonFlag := fs.Bool("json", false, "output trace as line-delimited JSON objects")
	prettyFlag := fs.Bool("pretty", false, "output trace as human-readable console text")
	fs.Usage = func() {
		fmt.Printf("Usage: %s [options] <tracefile>\n", os.Args[0])
		fs.PrintDefaults()
	}

	fs.Parse(os.Args[1:])
	if fs.NArg() == 0 || !(*jsonFlag || *prettyFlag) {
		fs.Usage()
		os.Exit(1)
	}
	args := fs.Args()

	f, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open: %s %v\n", os.Args[1], err)
		os.Exit(1)
	}
	tf, err := trace.NewReader(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening trace file: %v\n", err)
		os.Exit(1)
	}
	if *jsonFlag {
		if err := PrintJson(tf); err != nil {
			fmt.Fprintf(os.Stderr, "error printing json: %v\n", err)
			os.Exit(1)
		}
	} else if *prettyFlag {
		if err := PrintPretty(tf); err != nil {
			fmt.Fprintf(os.Stderr, "error printing pretty: %v\n", err)
			os.Exit(1)
		}
	}
}
