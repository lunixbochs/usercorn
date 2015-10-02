package models

import "fmt"

type ExitStatus int

func (e ExitStatus) Error() string {
	return fmt.Sprintf("exit %d", e)
}
