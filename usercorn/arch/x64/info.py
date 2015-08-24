from capstone import *
from unicorn import *
from unicorn.x86_const import *

bits = 64
radare = 'x86'
capstone_init = (CS_ARCH_X86, CS_MODE_64)
sp = UC_X86_REG_RSP
unicorn_init = (UC_ARCH_X86, UC_MODE_64)
regs = (
    (UC_X86_REG_RAX, "rax"),
    (UC_X86_REG_RBX, "rbx"),
    (UC_X86_REG_RCX, "rcx"),
    (UC_X86_REG_RDX, "rdx"),
    (UC_X86_REG_RSI, "rsi"),
    (UC_X86_REG_RDI, "rdi"),
    (UC_X86_REG_R8, "r8"),
    (UC_X86_REG_R9, "r9"),
    (UC_X86_REG_R10, "r10"),
    (UC_X86_REG_R11, "r11"),
    (UC_X86_REG_R12, "r12"),
    (UC_X86_REG_R13, "r13"),
    (UC_X86_REG_R14, "r14"),
    (UC_X86_REG_R15, "r15"),
)
