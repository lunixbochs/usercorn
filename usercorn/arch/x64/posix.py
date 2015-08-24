from unicorn.x86_const import *

regs = (X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_R10, X86_REG_R8, X86_REG_R9)

def syscall_args(cls):
    return cls.reg_read(X86_REG_RAX), [cls.reg_read(reg) for reg in regs]
