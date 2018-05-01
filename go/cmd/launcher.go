package cmd

import (
	"fmt"
	"os"
	"strings"
)

type command struct {
	name, desc string
	main       func(args []string)
}

var commands map[string]*command
var order []string
var pad int

func init() { commands = make(map[string]*command) }

func Register(name, desc string, main func(args []string)) {
	if len(name) > pad {
		pad = len(name)
	}
	commands[name] = &command{name, desc, main}
	order = append(order, name)
}

func Main() {
	usage := func() {
		fmt.Fprintln(os.Stderr, "Commands:")
		fstr := fmt.Sprintf("%%-%ds | %%s\n", pad)
		for _, name := range order {
			cmd := commands[name]
			fmt.Fprintf(os.Stderr, fstr, cmd.name, cmd.desc)
		}
		fmt.Fprintf(os.Stderr, "\nExample: %s run -trace -symfile bins/x86_64.linux.elf\n\n", os.Args[0])
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	} else {
		cmd, ok := commands[os.Args[1]]
		if ok {
			args := append([]string{strings.Join(os.Args[:2], " ")}, os.Args[2:]...)
			cmd.main(args)
		} else {
			fmt.Fprintf(os.Stderr, "Command '%s' not found.\n\n", os.Args[1])
			usage()
			os.Exit(1)
		}
	}
}
