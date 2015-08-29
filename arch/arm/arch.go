package arm

import (
    uc "github.com/lunixbochs/unicorn"
    cs "github.com/bnagy/gapstone"
    "../arch"
)

var Arch = &arch.Arch{
    Bits: 32,
    Radare: "arm",
    CS_ARCH: cs.CS_ARCH_ARM,
    CS_MODE: cs.CS_MODE_ARM,
    UC_ARCH: uc.UC_ARCH_ARM,
    UC_MODE: uc.UC_MODE_ARM,
    SP: uc.UC_ARM_REG_SP,
    Syscall: nil,
    Interrupt: interrupt,
}

func interrupt() {

}
