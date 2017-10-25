static const PCHAR command_list[] = {
	"add",
	"adc",
	"and",
	"xor",
	"push",
	"pusha",
	"popa",
	"jo",
	"jb",
	"jz",
	"jbe",
	"test",
	"xchg",
	"nop",
	"mov",
	"movs",
	"cmps",
	"loopne",
	"loope",
	"loop",
	"jcxz",
	"in",
	"out",
	"int1",
	"hlt",
	"cmc",
	"or",
	"sbb",
	"sub",
	"cmp",
	"dec",
	"pop",
	"imul",
	"ins",
	"outs",
	"js",
	"jp",
	"jl",
	"jle",
	"lea",
	"cwde",
	"cdq",
	"call",
	"wait",
	"pushf",
	"popf",
	"sahf",
	"lahf",
	"stos",
	"lods",
	"scas",
	"enter",
	"leave",
	"ret",
	"int3",
	"int",
	"into",
	"iret",
	"esc",
	"clc",
	"stc",
	"cli",
	"sti",
	"cld",
	"std",
	"rol",
	"ror",
	"rcl",
	"rcr",
	"shl",
	"shr",
	"sal",
	"sar",
	"test",
	"not",
	"neg",
	"mul",
	"div",
	"idiv",
	"inc",
	"retn",
	"jmp",
	"seto",
	"setno",
	"setb",
	"setnb",
	"setz",
	"setnz",
	"setbe",
	"setnbe",
	"movzx"
};

static const PCHAR register_list32[] = {
	"eax",
	"ebx",
	"ecx",
	"edx",
	"edi",
	"esi",
	"esp",
	"ebp"
};

static const PCHAR register_list8[] = {
	"al",
	"bl",
	"cl",
	"dl",
	"ah",
	"bh",
	"ch",
	"dh"
};

static const PCHAR register_list16[] = {
	"ax",
	"bx",
	"cx",
	"dx"
};

static const PCHAR register_list8_low[] = {
	"al",
	"bl",
	"cl",
	"dl"
};

static const PCHAR register_list8_high[] = {
	"ah",
	"bh",
	"ch",
	"dh"
};

static const PCHAR segment_registers[] = {
	"es",
	"cs",
	"ss",
	"ds",
	"fs",
	"gs"
};

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

static const BYTE prefix_list[] = {0xf0, 0xf3, 0xf2, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x77};
static const PCHAR prefix_list_names[] = {	"lock",
											"rep[e]",
											"repne",
											"CS",
											"SS",
											"DS",
											"ES",
											"FS",
											"GS",
											"OP16",
											"ADDRESS"};