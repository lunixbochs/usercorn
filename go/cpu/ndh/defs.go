package ndh

const (
	R0 = iota
	R1
	R2
	R3
	R4
	R5
	R6
	R7
	PC
	BP
	SP

	ZF
	AF
	BF
)

const (
	OP_PUSH = 0x01
	OP_POP  = 0x03

	OP_MOV = 0x04

	OP_ADD = 0x06
	OP_SUB = 0x07
	OP_MUL = 0x08
	OP_DIV = 0x09
	OP_INC = 0x0A
	OP_DEC = 0x0B

	OP_OR  = 0x0C
	OP_AND = 0x0D
	OP_XOR = 0x0E
	OP_NOT = 0x0F

	OP_JZ   = 0x10
	OP_JNZ  = 0x11
	OP_JMPS = 0x16
	OP_TEST = 0x17
	OP_CMP  = 0x18
	OP_CALL = 0x19
	OP_RET  = 0x1A
	OP_JMPL = 0x1B
	OP_END  = 0x1C
	OP_XCHG = 0x1D
	OP_JA   = 0x1E
	OP_JB   = 0x1F

	OP_SYSCALL = 0x30
	OP_NOP     = 0x02
)

const (
	OP_FLAG_REG_REG                 = 0x00
	OP_FLAG_REG_DIRECT08            = 0x01
	OP_FLAG_REG_DIRECT16            = 0x02
	OP_FLAG_REG                     = 0x03
	OP_FLAG_DIRECT16                = 0x04
	OP_FLAG_DIRECT08                = 0x05
	OP_FLAG_REGINDIRECT_REG         = 0x06
	OP_FLAG_REGINDIRECT_DIRECT08    = 0x07
	OP_FLAG_REGINDIRECT_DIRECT16    = 0x08
	OP_FLAG_REGINDIRECT_REGINDIRECT = 0x09
	OP_FLAG_REG_REGINDIRECT         = 0x0a
)

// Addressing mode
const (
	A_NONE = iota
	A_1REG
	A_2REG
	A_U8
	A_U16
	A_FLAG // Addressing mode read from next byte
)

type op struct {
	name string
	arg  int
}

var opData = map[int]op{
	OP_ADD:     op{"add", A_FLAG},
	OP_AND:     op{"and", A_FLAG},
	OP_CALL:    op{"call", A_FLAG},
	OP_CMP:     op{"cmp", A_FLAG},
	OP_DEC:     op{"dec", A_1REG},
	OP_DIV:     op{"div", A_FLAG},
	OP_END:     op{"end", A_NONE},
	OP_INC:     op{"inc", A_1REG},
	OP_JA:      op{"ja", A_U16},
	OP_JB:      op{"jb", A_U16},
	OP_JMPL:    op{"jmpl", A_U16},
	OP_JMPS:    op{"jmps", A_U8},
	OP_JNZ:     op{"jnz", A_U16},
	OP_JZ:      op{"jz", A_U16},
	OP_MOV:     op{"mov", A_FLAG},
	OP_MUL:     op{"mul", A_FLAG},
	OP_NOP:     op{"nop", A_NONE},
	OP_NOT:     op{"not", A_1REG},
	OP_OR:      op{"or", A_FLAG},
	OP_POP:     op{"pop", A_1REG},
	OP_PUSH:    op{"push", A_FLAG},
	OP_RET:     op{"ret", A_NONE},
	OP_SUB:     op{"sub", A_FLAG},
	OP_SYSCALL: op{"syscall", A_NONE},
	OP_TEST:    op{"test", A_2REG},
	OP_XCHG:    op{"xchg", A_2REG},
	OP_XOR:     op{"xor", A_FLAG},
}
