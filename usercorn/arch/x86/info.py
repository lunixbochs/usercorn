from capstone import *
from unicorn import *
from unicorn.x86_const import *

bits = 32
radare = 'x86'
capstone_init = (CS_ARCH_X86, CS_MODE_32)
sp = X86_REG_ESP
unicorn_init = (UC_ARCH_X86, UC_MODE_32)
regs = (
    (X86_REG_EAX, "rax"),
    (X86_REG_EBX, "rbx"),
    (X86_REG_ECX, "rcx"),
    (X86_REG_EDX, "rdx"),
    (X86_REG_ESI, "rsi"),
    (X86_REG_EDI, "rdi"),
)
