package arch

import (
	"github.com/pkg/errors"

	"github.com/lunixbochs/usercorn/go/arch/arm"
	"github.com/lunixbochs/usercorn/go/arch/arm64"
	"github.com/lunixbochs/usercorn/go/arch/bpf"
	"github.com/lunixbochs/usercorn/go/arch/m68k"
	"github.com/lunixbochs/usercorn/go/arch/mips"
	"github.com/lunixbochs/usercorn/go/arch/ndh"
	"github.com/lunixbochs/usercorn/go/arch/sparc"
	"github.com/lunixbochs/usercorn/go/arch/x86"
	"github.com/lunixbochs/usercorn/go/arch/x86_16"
	"github.com/lunixbochs/usercorn/go/arch/x86_64"
	"github.com/lunixbochs/usercorn/go/models"
)

var archMap = map[string]*models.Arch{
	"arm":    arm.Arch,
	"arm64":  arm64.Arch,
	"bpf":    bpf.Arch,
	"m68k":   m68k.Arch,
	"mips":   mips.Arch,
	"ndh":    ndh.Arch,
	"sparc":  sparc.Arch,
	"x86":    x86.Arch,
	"x86_16": x86_16.Arch,
	"x86_64": x86_64.Arch,
}

func GetArch(name, os string) (*models.Arch, *models.OS, error) {
	a, ok := archMap[name]
	if !ok {
		return nil, nil, errors.Errorf("Arch '%s' not found.", name)
	}
	o, ok := a.OS[os]
	if !ok {
		return nil, nil, errors.Errorf("OS '%s' not found for arch '%s'.", os, name)
	}
	return a, o, nil
}
