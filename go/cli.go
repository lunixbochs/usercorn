package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	verbose := flag.Bool("v", false, "verbose output")
	strace := flag.Bool("strace", false, "trace syscalls")
	mtrace := flag.Bool("mtrace", false, "trace memory access")
	etrace := flag.Bool("etrace", false, "trace execution")
	prefix := flag.String("prefix", "", "library load prefix")
	flag.Usage = func() {
		fmt.Printf("Usage: %s [options] <exe> [args...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}
	absPrefix, err := filepath.Abs(*prefix)
	if err != nil {
		log.Fatal(err)
	}
	corn, err := NewUsercorn(args[0], absPrefix)
	if err != nil {
		log.Fatal(err)
	}
	corn.Verbose = *verbose
	corn.TraceSys = *strace
	corn.TraceMem = *mtrace
	corn.TraceExec = *etrace
	err = corn.Run(args...)
	if err != nil {
		log.Fatal(err)
	}
}
