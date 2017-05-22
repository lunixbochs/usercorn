package tests

import (
	"testing"

	"github.com/lunixbochs/usercorn/go"
	"github.com/lunixbochs/usercorn/go/models"
)

func BenchmarkRewind(b *testing.B) {
	u, err := usercorn.NewUsercorn("../../bins/x86.linux.elf", nil)
	if err != nil {
		b.Fatal(err)
	}
	err = u.Run(nil, nil)
	if _, ok := err.(models.ExitStatus); err != nil && !ok {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		u.Rewind(1, 0)
		pc, _ := u.RegRead(u.Arch().PC)
		u.Start(pc, 0)
	}
}
