from capstone import *
from unicorn import *
from unicorn.x86_const import *

bits = 32
radare = 'x86'
capstone_init = (CS_ARCH_X86, CS_MODE_32)
sp = UC_X86_REG_ESP
unicorn_init = (UC_ARCH_X86, UC_MODE_32)
regs = (
    (UC_X86_REG_EAX, "rax"),
    (UC_X86_REG_EBX, "rbx"),
    (UC_X86_REG_ECX, "rcx"),
    (UC_X86_REG_EDX, "rdx"),
    (UC_X86_REG_ESI, "rsi"),
    (UC_X86_REG_EDI, "rdi"),
)
