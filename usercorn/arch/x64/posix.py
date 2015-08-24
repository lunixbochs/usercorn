from unicorn.x86_const import *

regs = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9)

def syscall_args(cls):
    return cls.reg_read(UC_X86_REG_RAX), [cls.reg_read(reg) for reg in regs]
