package main

import (
	"github.com/lunixbochs/usercorn/go/cmd"

	_ "github.com/lunixbochs/usercorn/go/cmd/run"

	_ "github.com/lunixbochs/usercorn/go/cmd/bpf"
	_ "github.com/lunixbochs/usercorn/go/cmd/cfg"
	_ "github.com/lunixbochs/usercorn/go/cmd/cgc"
	_ "github.com/lunixbochs/usercorn/go/cmd/com"
	_ "github.com/lunixbochs/usercorn/go/cmd/fuzz"
	_ "github.com/lunixbochs/usercorn/go/cmd/imgtrace"
	_ "github.com/lunixbochs/usercorn/go/cmd/repl"
	_ "github.com/lunixbochs/usercorn/go/cmd/shellcode"
	_ "github.com/lunixbochs/usercorn/go/cmd/trace"
)

func main() { cmd.Main() }
