package bpf

const (
	// Instruction "Class"
	// class = op & 0xf
	CLASS_LD   = 0x00
	CLASS_LDX  = 0x01
	CLASS_ST   = 0x02
	CLASS_STX  = 0x03
	CLASS_ALU  = 0x04
	CLASS_JMP  = 0x05
	CLASS_RET  = 0x06
	CLASS_MISC = 0x07

	//[> ld/ldx fields <]
	//#define BPF_SIZE(code)  ((code) & 0x18)
	// Only cares about 2 bits
	SIZE_W = 0x00
	SIZE_H = 0x08
	SIZE_B = 0x10
	//#define BPF_MODE(code)  ((code) & 0xe0)
	MODE_IMM = 0x00
	MODE_ABS = 0x20
	MODE_IND = 0x40
	MODE_MEM = 0x60
	MODE_LEN = 0x80
	MODE_MSH = 0xa0

	MISC_TAX = 0x00
	MISC_TXA = 0x80

	//[> alu/jmp fields <]
	//#define BPF_OP(code)    ((code) & 0xf0)
	ALU_ADD = 0x00
	ALU_SUB = 0x10
	ALU_MUL = 0x20
	ALU_DIV = 0x30
	ALU_OR  = 0x40
	ALU_AND = 0x50
	ALU_LSH = 0x60
	ALU_RSH = 0x70
	ALU_NEG = 0x80
	ALU_MOD = 0x90
	ALU_XOR = 0xa0

	JMP_JA   = 0x00
	JMP_JEQ  = 0x10
	JMP_JGT  = 0x20
	JMP_JGE  = 0x30
	JMP_JSET = 0x40
	//#define BPF_SRC(code)   ((code) & 0x08)
	// Addressing modes?
	// TODO: Are these different based on the CLASS?
	BPF_K = 0x00
	BPF_X = 0x08
	BPF_A = 0x10

	OP_LD_B     = CLASS_LD | SIZE_B
	OP_LD_H     = CLASS_LD | SIZE_H
	OP_LD_W     = CLASS_LD | SIZE_W
	OP_LDX_B    = CLASS_LDX | SIZE_B
	OP_LDX_W    = CLASS_LDX | SIZE_W
	OP_ST       = CLASS_ST
	OP_STX      = CLASS_STX
	OP_JMP_JA   = CLASS_JMP | JMP_JA
	OP_JMP_JEQ  = CLASS_JMP | JMP_JEQ
	OP_JMP_JGT  = CLASS_JMP | JMP_JGT
	OP_JMP_JGE  = CLASS_JMP | JMP_JGE
	OP_JMP_JSET = CLASS_JMP | JMP_JSET
	OP_ALU_ADD  = CLASS_ALU | ALU_ADD
	OP_ALU_SUB  = CLASS_ALU | ALU_SUB
	OP_ALU_MUL  = CLASS_ALU | ALU_MUL
	OP_ALU_DIV  = CLASS_ALU | ALU_DIV
	OP_ALU_MOD  = CLASS_ALU | ALU_MOD
	OP_ALU_NEG  = CLASS_ALU | ALU_NEG
	OP_ALU_AND  = CLASS_ALU | ALU_AND
	OP_ALU_OR   = CLASS_ALU | ALU_OR
	OP_ALU_XOR  = CLASS_ALU | ALU_XOR
	OP_ALU_LSH  = CLASS_ALU | ALU_LSH
	OP_ALU_RSH  = CLASS_ALU | ALU_RSH
	OP_MISC_TAX = CLASS_MISC | MISC_TAX
	OP_MISC_TXA = CLASS_MISC | MISC_TXA
	OP_RET_A    = CLASS_RET | BPF_A
	OP_RET_IMM  = CLASS_RET | BPF_K
	OP_RET_X    = CLASS_RET | BPF_X

	// Instructions (addressing mode included)
	OP_LD_B_ABS  = OP_LD_B | MODE_ABS
	OP_LD_B_IND  = OP_LD_B | MODE_IND
	OP_LD_H_ABS  = OP_LD_H | MODE_ABS
	OP_LD_H_IND  = OP_LD_H | MODE_IND
	OP_LD_W_ABS  = OP_LD_W | MODE_ABS
	OP_LD_W_IND  = OP_LD_W | MODE_IND
	OP_LD_W_IMM  = OP_LD_W | MODE_IMM
	OP_LD_W_MEM  = OP_LD_W | MODE_MEM
	OP_LDX_W_IND = OP_LDX_W | MODE_IND
	OP_LDX_W_MEM = OP_LDX_W | MODE_MEM
	OP_LDX_W_MSH = OP_LDX_W | MODE_MSH
	OP_LDX_W_LEN = OP_LDX_W | MODE_LEN
	OP_LDX_W_IMM = OP_LDX_W | MODE_IMM
	OP_LDX_B_MSH = OP_LDX_B | MODE_MSH
	//OP_ST              = OP_ST
	//OP_STX             = OP_STX
	OP_ADD_X           = OP_ALU_ADD | BPF_X
	OP_ADD_IMM         = OP_ALU_ADD | BPF_K
	OP_SUB_X           = OP_ALU_SUB | BPF_X
	OP_SUB_IMM         = OP_ALU_SUB | BPF_K
	OP_MUL_X           = OP_ALU_MUL | BPF_X
	OP_MUL_IMM         = OP_ALU_MUL | BPF_K
	OP_DIV_X           = OP_ALU_DIV | BPF_X
	OP_DIV_IMM         = OP_ALU_DIV | BPF_K
	OP_MOD_X           = OP_ALU_MOD | BPF_X
	OP_MOD_IMM         = OP_ALU_MOD | BPF_K
	OP_NEG             = OP_ALU_NEG
	OP_AND_X           = OP_ALU_AND | BPF_X
	OP_AND_IMM         = OP_ALU_AND | BPF_K
	OP_OR_X            = OP_ALU_OR | BPF_X
	OP_OR_IMM          = OP_ALU_OR | BPF_K
	OP_XOR_X           = OP_ALU_XOR | BPF_X
	OP_XOR_IMM         = OP_ALU_XOR | BPF_K
	OP_LSH_X           = OP_ALU_LSH | BPF_X
	OP_LSH_IMM         = OP_ALU_LSH | BPF_K
	OP_RSH_X           = OP_ALU_RSH | BPF_X
	OP_RSH_IMM         = OP_ALU_RSH | BPF_K
	OP_TAX             = OP_MISC_TAX
	OP_TXA             = OP_MISC_TXA
	OP_JMP_JEQ_NOELSE  = OP_JMP_JEQ | BPF_X
	OP_JMP_JEQ_ELSE    = OP_JMP_JEQ | BPF_K
	OP_JMP_JGT_NOELSE  = OP_JMP_JGT | BPF_X
	OP_JMP_JGT_ELSE    = OP_JMP_JGT | BPF_K
	OP_JMP_JGE_NOELSE  = OP_JMP_JGE | BPF_X
	OP_JMP_JGE_ELSE    = OP_JMP_JGE | BPF_K
	OP_JMP_JSET_NOELSE = OP_JMP_JSET | BPF_X
	OP_JMP_JSET_ELSE   = OP_JMP_JSET | BPF_K
)

/*
   Mode Syntax       Description

   0    x/%x         Register X
   1    [k]          BHW at byte offset k in the packet
   2    [x + k]      BHW at the offset X + k in the packet
   3    M[k]         Word at offset k in M[]
   4    #k           Literal value stored in k
   5    4*([k]&0xf)  Lower nibble * 4 at byte offset k in the packet
   6    L            Jump label L
   7    #k,Lt,Lf     Jump to Lt if true, otherwise jump to Lf
   8    #k,Lt        Jump to Lt if predicate is true
   9    a/%a         Accumulator A
  10    extension    BPF extension
*/

const (
	A_X     = iota
	A_ABS   // [k]
	A_IND   // [x + k]
	A_MEM   // M[k]
	A_IMM   // #k
	A_MSH   // 4*([k]&0xf)
	A_JABS  // Label/k
	A_JELSE // if true lt, else lf
	A_J     // if true lt, else fallthrough
	A_A
	A_LEN
	A_NONE // for txa/tax
)

type op struct {
	name string
	arg  int
}

var opCodes = map[uint16]op{
	OP_RET_A:           op{"ret", A_A}, // TODO: Is RET_A real?
	OP_RET_IMM:         op{"ret", A_IMM},
	OP_RET_X:           op{"ret", A_X},
	OP_LD_B_ABS:        op{"ldb", A_ABS},
	OP_LD_B_IND:        op{"ldb", A_IND},
	OP_LD_H_ABS:        op{"ldh", A_ABS},
	OP_LD_H_IND:        op{"ldh", A_IND},
	OP_LD_W_ABS:        op{"ld", A_ABS},
	OP_LD_W_IND:        op{"ld", A_IND},
	OP_LD_W_IMM:        op{"ldi", A_IMM},
	OP_LD_W_MEM:        op{"ld", A_MEM},
	OP_LDX_W_IND:       op{"ldx", A_IND},
	OP_LDX_W_MEM:       op{"ldx", A_MEM},
	OP_LDX_W_MSH:       op{"ldx", A_MSH},
	OP_LDX_W_LEN:       op{"ldx", A_LEN},
	OP_LDX_W_IMM:       op{"ldxi", A_IMM},
	OP_LDX_B_MSH:       op{"ldxb", A_MSH},
	OP_ST:              op{"st", A_MEM},
	OP_STX:             op{"stx", A_MEM},
	OP_JMP_JA:          op{"jmp", A_JABS},
	OP_JMP_JEQ_NOELSE:  op{"jeq", A_J},
	OP_JMP_JEQ_ELSE:    op{"jeq", A_JELSE},
	OP_JMP_JGT_NOELSE:  op{"jgt", A_J},
	OP_JMP_JGT:         op{"jgt", A_JELSE},
	OP_JMP_JGE_NOELSE:  op{"jge", A_J},
	OP_JMP_JGE:         op{"jge", A_JELSE},
	OP_JMP_JSET_NOELSE: op{"jset", A_J},
	OP_JMP_JSET:        op{"jset", A_JELSE},
	OP_ADD_X:           op{"add", A_X},
	OP_ADD_IMM:         op{"add", A_IMM},
	OP_SUB_X:           op{"sub", A_X},
	OP_SUB_IMM:         op{"sub", A_IMM},
	OP_MUL_X:           op{"mul", A_X},
	OP_MUL_IMM:         op{"mul", A_IMM},
	OP_DIV_X:           op{"div", A_X},
	OP_DIV_IMM:         op{"div", A_IMM},
	OP_MOD_X:           op{"mod", A_X},
	OP_MOD_IMM:         op{"mod", A_IMM},
	OP_NEG:             op{"neg", A_A},
	OP_AND_X:           op{"and", A_X},
	OP_AND_IMM:         op{"and", A_IMM},
	OP_OR_X:            op{"or", A_X},
	OP_OR_IMM:          op{"or", A_IMM},
	OP_XOR_X:           op{"xor", A_X},
	OP_XOR_IMM:         op{"xor", A_IMM},
	OP_LSH_X:           op{"lsh", A_X},
	OP_LSH_IMM:         op{"lsh", A_IMM},
	OP_RSH_X:           op{"rsh", A_X},
	OP_RSH_IMM:         op{"rsh", A_IMM},
	OP_TAX:             op{"tax", A_NONE},
	OP_TXA:             op{"txa", A_NONE},
}
