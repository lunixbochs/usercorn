from capstone import *
from unicorn import *
from unicorn.x86_const import *

bits = 64
radare = 'x86'
capstone_init = (CS_ARCH_X86, CS_MODE_64)
sp = X86_REG_RSP
unicorn_init = (UC_ARCH_X86, UC_MODE_64)
regs = (
    (X86_REG_RAX, "rax"),
    (X86_REG_RBX, "rbx"),
    (X86_REG_RCX, "rcx"),
    (X86_REG_RDX, "rdx"),
    (X86_REG_RSI, "rsi"),
    (X86_REG_RDI, "rdi"),
    (X86_REG_R8, "r8"),
    (X86_REG_R9, "r9"),
    (X86_REG_R10, "r10"),
    (X86_REG_R11, "r11"),
    (X86_REG_R12, "r12"),
    (X86_REG_R13, "r13"),
    (X86_REG_R14, "r14"),
    (X86_REG_R15, "r15"),
)
