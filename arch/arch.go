package arch

import (
	"fmt"

	"../models"
	"./arm"
	"./arm64"
	"./mips"
	"./x86"
	"./x86_64"
)

var archMap = map[string]*models.Arch{
	"arm":    arm.Arch,
	"arm64":  arm64.Arch,
	"mips":   mips.Arch,
	"x86":    x86.Arch,
	"x86_64": x86_64.Arch,
}

func GetArch(name, os string) (*models.Arch, error) {
	if a, ok := archMap[name]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("Arch '%s' not found.", name)
}
