package models

import (
	"flag"
	"fmt"
	"strings"
)

func PrintFlags(flags []*flag.Flag) {
	wname := 0
	wdef := 0
	for _, f := range flags {
		if len(f.Name) > wname {
			wname = len(f.Name)
		}
		if len(f.DefValue) > wdef {
			wdef = len(f.DefValue)
		}
	}
	wdesc := 80 - wname - wdef - 7

	namefmt := fmt.Sprintf("%%-%ds", wname)
	deffmt := fmt.Sprintf("%%-%ds ", wdef+2)
	lpad := strings.Repeat(" ", wname+wdef+7)
	for _, f := range flags {
		fmt.Printf("  -"+namefmt, f.Name)
		if f.DefValue != "" && f.DefValue != "[]" {
			fmt.Printf(" "+deffmt, "("+f.DefValue+")")
		} else {
			fmt.Printf(" "+deffmt, "  ")
		}
		for i := 0; i < len(f.Usage); {
			if i > 0 {
				fmt.Printf("%s", lpad)
			}
			l := wdesc
			skip := false
			if i+wdesc > len(f.Usage) {
				l = len(f.Usage) - i
			} else {
				// split on newline or space if present
				s := strings.LastIndexAny(f.Usage[i:i+l], " \n")
				if s > 0 {
					l = s
					skip = true
				}
			}
			fmt.Printf("%s\n", f.Usage[i:i+l])
			i += l
			if skip {
				i += 1
			}
		}
	}
}
