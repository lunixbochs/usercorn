package repl

import (
	"fmt"
	"github.com/lunixbochs/luaish"
	"github.com/lunixbochs/readline"

	"github.com/lunixbochs/usercorn/go/models"
)

func Run(u models.Usercorn) error {
	u.Gate().Lock()
	rl, err := readline.NewEx(&readline.Config{})
	if err != nil {
		return err
	}
	go func() {
		defer func() {
			u.Exit(models.ExitStatus(0))
			u.Gate().Unlock()
		}()

		rl.SetPrompt("> ")
		L := lua.NewState()
		defer L.Close()
		for {
			ln := rl.Line()
			if ln.CanContinue() {
				continue
			} else if ln.CanBreak() {
				break
			}
			if _, err := L.LoadString(ln.Line); err == nil {
				if err := L.DoString(ln.Line); err != nil {
					fmt.Println(err)
				}
			} else {
				fmt.Println(err)
			}
		}
	}()
	return nil
}
