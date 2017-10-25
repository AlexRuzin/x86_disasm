#include <Windows.h>
#include <stdio.h>

#include "shared.h"
#include "visual.h"

#define _S					static
#define ERROR_CODE			UINT
#define FAIL(x)				x ? FALSE : TRUE
#define ERROR(x)			{printf("ERROR: %s", x); Sleep(INFINITE);}
#define DECODE_ERROR(x,y,z)	if (FAIL(x)) {printf("DECODE ERROR at address 0x%08x [0x%08x]", z, y); Sleep(INFINITE);}
#define NOP					__asm {nop}


#define STATIC_FILE			"J:\\x86_disasm\\Release\\test_binary.exe"

#define PRINT_INSTRUCTIONS

#define OPCODE				BYTE
#define MODRM				BYTE
#define PREFIX				BYTE

#define HALT_RAW_OFFSET		0x7e4

// Groupings
#define GP_80_83			0x1	
#define GP_0F				0x0f

// Modrm function types
#define MODRM_STANDARD		0
#define MODRM_NOTENCODED	1		// This is for instructions like LEA (0x8d), where no bus length and modrm direction are encoded

// SIB function types
#define SIB_STANDARD		0
#define SIB_NOTENCODED		1		// The direction of data is not encoded into the modrm byte

// Group modrm function types
#define GROUP_STANDARD		0
#define GROUP_SINGLE		1
#define GROUP_IMM8_OR_CONST	2

// Error codes
#define GROUP_ALREADY_ENCODED 1

// Commands
#define C_ADD				0
#define C_ADC				1
#define C_AND				2
#define C_XOR				3
#define C_PUSH				4
#define C_PUSHA				5
#define C_POPA				6
#define C_JO				7
#define C_JB				8
#define C_JZ				9
#define C_JBE				10
#define C_TEST				11
#define C_XCHG				12
#define C_NOP				13
#define C_MOV				14
#define C_MOVS				15
#define C_CMPS				16
#define C_LOOPNE			17
#define C_LOOPE				18
#define C_LOOP				19
#define C_JCXZ				20
#define C_IN				21
#define C_OUT				22
#define C_INT1				23
#define C_HLT				24
#define C_CMC				25
#define C_OR				26
#define C_SBB				27
#define C_SUB				28
#define C_CMP				29
#define C_DEC				30
#define C_POP				31
#define C_IMUL				32
#define C_INS				33
#define C_OUTS				34
#define C_JS				35
#define C_JP				36
#define C_JL				37
#define C_JLE				38
#define C_LEA				39
#define C_CWDE				40
#define C_CDQ				41
#define C_CALL				42
#define C_WAIT				43
#define C_PUSHF				44
#define C_POPF				45
#define C_SAHF				46
#define C_LAHF				47
#define C_STOS				48
#define C_LODS				49
#define C_SCAS				50
#define C_ENTER				51
#define C_LEAVE				52
#define C_RET				53
#define C_INT3				54
#define C_INT				55
#define C_INTO				56
#define C_IRET				57
#define C_ESC				58
#define C_CLC				59
#define C_STC				60
#define C_CLI				61
#define C_STI				62
#define C_CLD				63
#define C_STD				64
#define C_ROL				65
#define C_ROR				66
#define C_RCL				67
#define C_RCR				68
#define C_SHL				69
#define C_SHR				70
#define C_SAL				71
#define C_SAR				72
#define C_TEST				73
#define C_NOT				74
#define C_NEG				75
#define C_MUL				76
#define C_DIV				77
#define C_IDIV				78
#define C_INC				79
#define C_RETN				80
#define C_JMP				81
#define C_SETO				82
#define C_SETNO				83
#define C_SETB				84
#define C_SETNB				85
#define C_SETZ				86
#define C_SETNZ				87
#define C_SETBE				88
#define C_SETNBE			89
#define C_MOVZX				90

static const UINT gp_commands[][8] = {
	{C_ADD, C_OR, C_ADC, C_SBB, C_AND, C_SUB, C_XOR, C_CMP},
	{C_ROL, C_ROR, C_RCL, C_RCR, C_SHL, C_SHR, C_SAL, C_SAR},
	{C_TEST, C_TEST, C_NOT, C_NEG, C_MUL, C_IMUL, C_DIV, C_IDIV},
	{C_INC, C_DEC, C_CALL, C_CALL, C_JMP, C_JMP, C_PUSH},
	{C_INC, C_DEC, C_CALL, C_JMP, C_PUSH}
};

static const UINT cond_jump_commands[] = {
	C_JO, C_JB, C_JZ, C_JBE, C_JS, C_JP, C_JL, C_JLE
};

static const UINT group_0f_90[] = {
	C_SETO, C_SETNO, C_SETB, C_SETNB, C_SETZ, C_SETNZ, C_SETBE, C_SETNBE
};

#define TYPE_IMM8		1
#define TYPE_IMM16		2
#define TYPE_IMM32		3
#define TYPE_IMMPTR		4
#define TYPE_REG		5 // reg
#define TYPE_REG8		6
#define TYPE_REG16		7
#define TYPE_REG32		8
#define TYPE_REGPTR		9 // [reg]
#define TYPE_REGPTR8	10 // [reg + imm8]
#define TYPE_REGPTR32	11 // [reg + imm32]
#define TYPE_OFFSET8	12
#define TYPE_OFFSET16	13
#define TYPE_OFFSET32	14
#define TYPE_ABSOLUTE	15

#define REG_EAX			0
#define REG_EBX			1
#define REG_ECX			2
#define REG_EDX			3
#define REG_EDI			4
#define REG_ESI			5
#define REG_ESP			6
#define REG_EBP			7
#define REG_ES			0
#define REG_CS			1
#define REG_SS			2
#define REG_DS			3
#define REG_FS			4
#define REG_GS			5

#define BUS_BYTE		1
#define BUS_WORD		2
#define BUS_DWORD		3

#define JUMP_COND		1				//je
#define JUMP_NONCOND	2				//jmp, call
#define JUMP_COND_NEG	3				//jne

static const UINT modrm_regs[] = {REG_EAX, REG_ECX, REG_EDX, REG_EBX, REG_ESP, REG_EBP, REG_ESI, REG_EDI};

static const UINT seg_register_list[] = {REG_ES, REG_CS, REG_SS, REG_DS, REG_FS, REG_GS};

// Prefixes
#define PREFIX_LOCK		0xf0
#define PREFIX_REP_REPE	0xf3
#define PREFIX_REPNE	0xf2
#define PREFIX_CS		0x2e
#define PREFIX_SS		0x36
#define PREFIX_DS		0x3e
#define PREFIX_ES		0x26
#define PREFIX_FS		0x64
#define PREFIX_GS		0x65
#define PREFIX_OPERAND	0x66
#define PREFIX_ADDRESS	0x67

static const BYTE prefixes[] = {	PREFIX_LOCK,
									PREFIX_REP_REPE,
									PREFIX_REPNE,
									PREFIX_CS,
									PREFIX_SS,
									PREFIX_DS,
									PREFIX_ES,
									PREFIX_FS,
									PREFIX_GS,
									PREFIX_OPERAND,
									PREFIX_ADDRESS};

#define TYPE_NONE		0xffffffff
#define PARM_COMM		0
#define	PARM_OPCODE		1
#define PARM_TYPEDST	2
#define	PARM_DST		3
#define PARM_TYPESRC	4
#define PARM_SRC		5
#define PARM_BUS		6
static const DWORD single_opcode_nomodrm_commands[][7] =
//	command		opcode		type			dst				type			src				bus
{
	{C_NOP,		0x90,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE},
	{C_PUSH,	0x50,		TYPE_REG32,		REG_EAX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_PUSH,	0x51,		TYPE_REG32,		REG_ECX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_PUSH,	0x52,		TYPE_REG32,		REG_EDX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_PUSH,	0x53,		TYPE_REG32,		REG_EBX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_PUSH,	0x54,		TYPE_REG32,		REG_ESP,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_PUSH,	0x55,		TYPE_REG32,		REG_EBP,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_PUSH,	0x56,		TYPE_REG32,		REG_ESI,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_PUSH,	0x57,		TYPE_REG32,		REG_EDI,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_PUSH,	0x68,		TYPE_IMM32,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_PUSH,	0x6a,		TYPE_IMM8,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_BYTE},
	{C_PUSHA,	0x60,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_POPA,	0x61,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_XCHG,	0x91,		TYPE_REG32,		REG_ECX,		TYPE_REG32,		REG_EAX,		BUS_DWORD},
	{C_XCHG,	0x92,		TYPE_REG32,		REG_EDX,		TYPE_REG32,		REG_EAX,		BUS_DWORD},
	{C_XCHG,	0x93,		TYPE_REG32,		REG_EBX,		TYPE_REG32,		REG_EAX,		BUS_DWORD},
	{C_XCHG,	0x94,		TYPE_REG32,		REG_ESP,		TYPE_REG32,		REG_EAX,		BUS_DWORD},
	{C_XCHG,	0x95,		TYPE_REG32,		REG_EBP,		TYPE_REG32,		REG_EAX,		BUS_DWORD},
	{C_XCHG,	0x96,		TYPE_REG32,		REG_ESI,		TYPE_REG32,		REG_EAX,		BUS_DWORD},
	{C_XCHG,	0x97,		TYPE_REG32,		REG_EDI,		TYPE_REG32,		REG_EAX,		BUS_DWORD},
	{C_INC,		0x40,		TYPE_REG32,		REG_EAX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_INC,		0x41,		TYPE_REG32,		REG_ECX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_INC,		0x42,		TYPE_REG32,		REG_EDX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_INC,		0x43,		TYPE_REG32,		REG_EBX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_INC,		0x44,		TYPE_REG32,		REG_ESP,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_INC,		0x45,		TYPE_REG32,		REG_EBP,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_INC,		0x46,		TYPE_REG32,		REG_ESI,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_INC,		0x47,		TYPE_REG32,		REG_EDI,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_RET,		0xc3,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_RETN,	0xc2,		TYPE_IMM16,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_IN,		0xe4,		TYPE_REG8,		REG_EAX,		TYPE_IMM8,		TYPE_NONE,		BUS_DWORD},
	{C_IN,		0xe5,		TYPE_REG32,		REG_EAX,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},
	{C_OUT,		0xe6,		TYPE_IMM8,		TYPE_NONE,		TYPE_REG8,		REG_EAX,		BUS_BYTE},
	{C_OUT,		0xe7,		TYPE_IMM32,		TYPE_NONE,		TYPE_REG32,		REG_EAX,		BUS_DWORD},
	{C_HLT,		0xf4,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE},
	{C_CMC,		0xf5,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE},
	{C_POP,		0x58,		TYPE_REG32,		REG_EAX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_POP,		0x59,		TYPE_REG32,		REG_ECX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_POP,		0x5a,		TYPE_REG32,		REG_EDX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_POP,		0x5b,		TYPE_REG32,		REG_EBX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_POP,		0x5c,		TYPE_REG32,		REG_ESP,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_POP,		0x5d,		TYPE_REG32,		REG_EBP,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_POP,		0x5e,		TYPE_REG32,		REG_ESI,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_POP,		0x5f,		TYPE_REG32,		REG_EDI,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_DEC,		0x48,		TYPE_REG32,		REG_EAX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_DEC,		0x49,		TYPE_REG32,		REG_ECX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_DEC,		0x4a,		TYPE_REG32,		REG_EDX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_DEC,		0x4b,		TYPE_REG32,		REG_EBX,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_DEC,		0x4c,		TYPE_REG32,		REG_ESP,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_DEC,		0x4d,		TYPE_REG32,		REG_EBP,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_DEC,		0x4e,		TYPE_REG32,		REG_ESI,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_DEC,		0x4f,		TYPE_REG32,		REG_EDI,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_CWDE,	0x98,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE},
	{C_CDQ,		0x99,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE},
	{C_WAIT,	0x9b,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE},
	{C_TEST,	0xa8,		TYPE_REG8,		REG_EAX,		TYPE_IMM8,		TYPE_NONE,		BUS_BYTE},
	{C_TEST,	0xa9,		TYPE_REG32,		REG_EAX,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},
	{C_STOS,	0xaa,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_BYTE},
	{C_STOS,	0xab,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_LODS,	0xac,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_BYTE},
	{C_LODS,	0xad,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_SCAS,	0xae,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_BYTE},
	{C_SCAS,	0xaf,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_DWORD},
	{C_ENTER,	0xc8,		TYPE_IMM16,		TYPE_NONE,		TYPE_IMM8,		TYPE_NONE,		TYPE_NONE},
	{C_LEAVE,	0xc9,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE},
	
	{C_MOV,		0xa0,		TYPE_REG8,		REG_EAX,		TYPE_IMMPTR,	TYPE_NONE,		BUS_BYTE},
	{C_MOV,		0xa1,		TYPE_REG32,		REG_EAX,		TYPE_IMMPTR,	TYPE_NONE,		BUS_DWORD},
	{C_MOV,		0xa2,		TYPE_IMMPTR,	TYPE_NONE,		TYPE_REG8,		REG_EAX,		BUS_BYTE},
	{C_MOV,		0xb0,		TYPE_REG8,		REG_EAX,		TYPE_IMM8,		TYPE_NONE,		BUS_BYTE},
	{C_MOV,		0xa0,		TYPE_REG8,		REG_EAX,		TYPE_IMMPTR,	TYPE_NONE,		BUS_BYTE},
	{C_MOV,		0xa1,		TYPE_REG32,		REG_EAX,		TYPE_IMMPTR,	TYPE_NONE,		BUS_DWORD},
	{C_MOV,		0xa2,		TYPE_IMMPTR,	TYPE_NONE,		TYPE_REG8,		REG_EAX,		BUS_BYTE},
	{C_MOV,		0xa3,		TYPE_IMMPTR,	TYPE_NONE,		TYPE_REG32,		REG_EAX,		BUS_DWORD},

	{C_MOV,		0xb8,		TYPE_REG8,		REG_EAX,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},
	{C_MOV,		0xb9,		TYPE_REG8,		REG_ECX,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},
	{C_MOV,		0xba,		TYPE_REG8,		REG_EDX,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},
	{C_MOV,		0xbb,		TYPE_REG8,		REG_EBX,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},
	{C_MOV,		0xbc,		TYPE_REG8,		REG_ESP,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},
	{C_MOV,		0xbd,		TYPE_REG8,		REG_EBP,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},
	{C_MOV,		0xbe,		TYPE_REG8,		REG_ESI,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},
	{C_MOV,		0xbf,		TYPE_REG8,		REG_EDI,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},
	
	{C_MOVS,	0xa4,		TYPE_REG8,		REG_EDI,		TYPE_REG8,		REG_ESI,		BUS_BYTE},
	{C_MOVS,	0xa5,		TYPE_REG32,		REG_EDI,		TYPE_REG32,		REG_ESI,		BUS_DWORD},
	{C_CMPS,	0xa6,		TYPE_REG8,		REG_EDI,		TYPE_REG8,		REG_ESI,		BUS_BYTE},
	{C_CMPS,	0xa7,		TYPE_REG32,		REG_EDI,		TYPE_REG32,		REG_ESI,		BUS_DWORD},

	{C_PUSHF,	0x9c,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE},

	{C_CMP,		0x3c,		TYPE_REG8,		REG_EAX,		TYPE_IMM8,		TYPE_NONE,		BUS_BYTE},
	{C_CMP,		0x3d,		TYPE_REG32,		REG_EAX,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},

	{C_RET,		0xc2,		TYPE_IMM16,		TYPE_NONE,		TYPE_NONE,		TYPE_NONE,		BUS_WORD},

	{C_SUB,		0x2d,		TYPE_REG32,		REG_EAX,		TYPE_IMM32,		TYPE_NONE,		BUS_DWORD},

	{C_OR,		0x0d,		TYPE_REG32,		REG_EAX,		TYPE_IMM32,	TYPE_NONE,		BUS_DWORD}
};


typedef struct x86_instruction {
	PVOID				instruction;
	BYTE				opcode;
	BYTE				opcode_prefix;		// 0x0f for example (this does NOT include standard seg, lock, etc prefixes)
	BYTE				modrm;
	BYTE				prefix[3];
	BYTE				sib;

	BYTE				group;				// opcode group
	BYTE				command;

	UINT				size;
	UINT				counter;
	
	BYTE				databus;

	// Destination operand
	BYTE				type1;
	BYTE				reg1;
	union {
		DWORD			op18;
		DWORD			op116;
		DWORD			op132;
	};
	DWORD				offset1;				// [reg + imm32/imm8/imm16]

	// Source operand
	BYTE				type2;
	BYTE				reg2;
	union {
		DWORD			op28;
		DWORD			op216;
		DWORD			op232;
	};
	DWORD				offset2;

	// SIB
	BYTE				sibtype;			// dst or src?; Scalar imm or reg?
	DWORD				sibvalue;

	// Jumps
	union {
		DWORD			jmp_offset;
		DWORD			jmp_absolute;
	};
	BYTE				jmp_type;			// non-conditional, conditional, conditional-negated

	PVOID				next;				// Pointer to the next instruction
} x86_INSTRUCTION, *Px86_INSTRUCTION;

// Prototypes
static ERROR_CODE isolate_code_segment(PDWORD pe, PDWORD *code, PUINT size);
static ERROR_CODE decode(PVOID instruction, Px86_INSTRUCTION inst_data);
static ERROR_CODE decode_group(Px86_INSTRUCTION inst_data);
static VOID decode_group_operands(Px86_INSTRUCTION inst_data, DWORD type);
static ERROR_CODE decode_group_register(Px86_INSTRUCTION inst_data);
static VOID print_instruction(Px86_INSTRUCTION inst_data, UINT offset);
static ERROR_CODE decode_simple_instruction(Px86_INSTRUCTION inst_data, UINT command);
static ERROR_CODE decode_modrm(Px86_INSTRUCTION inst_data, DWORD type);
static VOID decode_sib(Px86_INSTRUCTION inst_data, DWORD type);
static ERROR_CODE decode_cond_jump(Px86_INSTRUCTION inst_data);
static ERROR_CODE decode_nonstandard(Px86_INSTRUCTION inst_data);