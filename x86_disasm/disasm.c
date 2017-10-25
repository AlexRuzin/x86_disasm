#include "disasm.h"

// sub dword ptr [esp], imm32

INT main(VOID)
{
	ERROR_CODE					status;

	PDWORD						file;
	UINT						file_size;

	PDWORD						code; 
	PVOID						inst_ptr;
	UINT						code_size;

	// Instruction chain
	Px86_INSTRUCTION			chain_start, chain_current;
	UINT						total_inst_len;

	// Load into memory
	status = (ERROR_CODE)read_raw_into_buffer(STATIC_FILE, &file_size, (LPVOID *)&file);
	if (FAIL(status)) {
		ERROR("Failure in loading target.");
	}

	// Isolate code segment
	status = isolate_code_segment(file, &code, &code_size);

	// Allocate chain & disassemble
	chain_start = (Px86_INSTRUCTION)HeapAlloc(GetProcessHeap(), 0, sizeof(x86_INSTRUCTION));
	ZeroMemory(chain_start, sizeof(x86_INSTRUCTION));
	chain_current = chain_start;
	total_inst_len = 0;
	status = decode(code, chain_start);
	DECODE_ERROR(status, chain_start, code);
#if defined(PRINT_INSTRUCTIONS)
	print_instruction((Px86_INSTRUCTION)chain_start, 0);
#endif
	total_inst_len = total_inst_len + chain_current->size;
	inst_ptr = (PVOID)((DWORD_PTR)code + chain_start->size);
	while (total_inst_len <= code_size) {

		chain_current->next = (PVOID)HeapAlloc(GetProcessHeap(), 0, sizeof(x86_INSTRUCTION));
		ZeroMemory(chain_current->next, sizeof(x86_INSTRUCTION));
		chain_current = (Px86_INSTRUCTION)chain_current->next;

		status = decode(inst_ptr, chain_current);
		DECODE_ERROR(status, chain_current, inst_ptr);

#if defined(PRINT_INSTRUCTIONS)
		print_instruction((Px86_INSTRUCTION)chain_current, total_inst_len);
#endif	

		inst_ptr = (PVOID)((DWORD_PTR)inst_ptr + chain_current->size);

		total_inst_len = total_inst_len + chain_current->size;

#if defined(HALT_RAW_OFFSET)
		if (total_inst_len == HALT_RAW_OFFSET) {
			printf("DEBUG: Disassembler halted at offset 0x%08x\n", HALT_RAW_OFFSET);
			NOP;
		}
#endif
	}

	printf("Disassembly complete.\n");
	Sleep(INFINITE);

	return;
}

// Disassembles an instruction
static ERROR_CODE decode(PVOID instruction, Px86_INSTRUCTION inst_data)
{
	ERROR_CODE				status;
	BYTE					opcode;

	UINT					i;

	opcode					= *(PBYTE)instruction;
	inst_data->instruction	= instruction;
	inst_data->opcode		= opcode;

	// Check for any prefixes //FIXME add support for multiple prefixes
	for (i = 0; i < sizeof(prefixes); i++) {
		if (inst_data->opcode == prefixes[i]) {
			inst_data->prefix[0] = inst_data->opcode;
			inst_data->size++;
			inst_data->opcode	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->modrm	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size + 1);
			opcode				= inst_data->opcode;
			break;
		}
	}

	// Check groups (0x80-0x83)
	if (	((opcode & 0xfc) == 0x80) ||	 //ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
			(opcode == 0xff)	||			// INC, DEC, CALL Ev, CALL Mp, JMP Ev, JMP Mp, PUSH Ev
			(opcode == 0x8f)	||			// POP Ev
			((opcode & 0xfe) == 0xf6) ||
			((opcode & 0xfe) == 0xc0) 
			) 
	{
		status = decode_group(inst_data);
		DECODE_ERROR(status, inst_data, instruction);
		return TRUE;
	}

	// Check single-byte opcodes
	for (i = 0; i < (sizeof(single_opcode_nomodrm_commands) / sizeof(single_opcode_nomodrm_commands[0])); i++) {
		if (opcode == single_opcode_nomodrm_commands[i][PARM_OPCODE]) {
			inst_data->size++;
			status = decode_simple_instruction(inst_data, i);
			DECODE_ERROR(status, inst_data, instruction);
			return TRUE;
		}
	}

	// Check opcode + modrm (or Eb, Gb)
	if (	!(opcode & 0xcc) ||
			((opcode & 0xfc) == 0x88) ||
			((opcode & 0xfe) == 0xc6) ||// mov Ev, Iz; mov Eb, Ib (c6, c7)
			((opcode & 0xfc) == 0x84) ||//test,xchg
			((opcode & 0xfc) == 0x28) ||
			((opcode & 0xfc) == 0x38) ||//cmp Eb,Gb
			((opcode & 0xfc) == 0x18) ||
			((opcode & 0xfc) == 0x08)	//or
			) {

		inst_data->size	= sizeof(OPCODE) + sizeof(MODRM) + inst_data->size;

		switch (opcode & 0xfc)
		{
		case 0:		//add
			inst_data->command = C_ADD;
			break;
		case 0x10:	//adc
			inst_data->command = C_ADC;
			break;
		case 0x20:	//and
			inst_data->command = C_AND;
			break;
		case 0x30:	//xor
			inst_data->command = C_XOR;
			break;
		case 0x88: //mov
			inst_data->command = C_MOV;
			break;
		case 0xc4: //mov, special opcodes 0xc7, 0xc6
			inst_data->command	= C_MOV;
			break;
		case 0x84:
			inst_data->command	= C_TEST;
			break;
		case 0x28:
			inst_data->command	= C_SUB;
			break;
		case 0x38:
			inst_data->command	= C_CMP;
			break;
		case 0x18:
			inst_data->command  = C_SBB;
			break;
		case 0x08:
			inst_data->command	= C_OR;
			break;
		default:
			return FALSE;
		}



		status = decode_modrm(inst_data, MODRM_STANDARD);
		DECODE_ERROR(status, inst_data, instruction);
		return TRUE;
	}

	// Check for other opcode + modrm instructions
	if (opcode == 0x8d) { //lea
		inst_data->size			= sizeof(OPCODE) + sizeof(MODRM);
		inst_data->command		= C_LEA;
		inst_data->databus		= BUS_DWORD;
		status = decode_modrm(inst_data, MODRM_NOTENCODED);
		DECODE_ERROR(status, inst_data, instruction);
		return TRUE;
	}

	// Conditional jumps (0x70-0x7f branch)
	if ((opcode & 0xf0) == 0x70) {
		inst_data->size++;
		status = decode_cond_jump(inst_data);
		DECODE_ERROR(status, inst_data, instruction);
		return TRUE;
	}

	// Conditional jumps (0x0f prefix; 0x80-0x87 branch)
	if (opcode == GP_0F) {
		inst_data->opcode_prefix	= opcode;
		inst_data->opcode			= *(PBYTE)((DWORD_PTR)inst_data->instruction + sizeof(PREFIX));
		inst_data->modrm			= *(PBYTE)((DWORD_PTR)inst_data->instruction + sizeof(PREFIX) + sizeof(OPCODE));
		inst_data->size				= sizeof(PREFIX) + sizeof(OPCODE) + sizeof(MODRM);
		switch (inst_data->opcode & 0xf0)
		{
		case 0x80: //jo, jno imm32 etc
			status = decode_cond_jump(inst_data);
			DECODE_ERROR(status, inst_data, instruction);
			break;
		case 0x90: //setz, etc
			inst_data->command		= group_0f_90[inst_data->opcode & 0xf];
			inst_data->databus		= BUS_BYTE;
			inst_data->type1		= TYPE_REG;
			inst_data->reg1			= modrm_regs[inst_data->modrm & 0x7]; //FIXME (unknown which field is for what)
			break;
		case 0xb0: //movzx
			inst_data->command		= C_MOVZX;
			inst_data->databus		= BUS_DWORD;
			status = decode_modrm(inst_data, MODRM_NOTENCODED);
			DECODE_ERROR(status, inst_data, instruction);
			break;
		default:
			return FALSE;
		}
		return TRUE;
	}

	// Check for all other non-standard opcodes
	status = decode_nonstandard(inst_data);
	DECODE_ERROR(status, inst_data, instruction);

	return TRUE;
}

static ERROR_CODE decode_nonstandard(Px86_INSTRUCTION inst_data)
{
	/*
	// Check for 0xff15 (call [mem])
	if (*(PWORD)inst_data->instruction == 0x15ff) {
		inst_data->opcode			= 0x15;
		inst_data->opcode_prefix	= 0xff;
		inst_data->command			= C_CALL;
		inst_data->type1			= TYPE_IMMPTR;
		inst_data->op132			= *(PDWORD)((DWORD_PTR)inst_data->instruction + sizeof(PREFIX) + sizeof(OPCODE));
		inst_data->size				= sizeof(PREFIX) + sizeof(OPCODE) + sizeof(DWORD);
		inst_data->databus			= BUS_DWORD;
		return TRUE;
	}*/

	// call, jmp imm32
	if ((*(PBYTE)inst_data->instruction	== 0xe8) || 
		(*(PBYTE)inst_data->instruction	== 0xe9) || 
		(*(PBYTE)inst_data->instruction == 0xeb)) {
		inst_data->opcode			= *(PBYTE)inst_data->instruction;
		switch (*(PBYTE)inst_data->instruction & 1)
		{
		case 0x0:
			inst_data->command			= C_CALL;
			break;
		case 0x1:
			inst_data->command			= C_JMP;
			break;
		}
		
		switch (inst_data->opcode) 
		{
		case 0xeb:
			inst_data->type1		= TYPE_IMM8;
			inst_data->op18			= *(PBYTE)((DWORD_PTR)inst_data->instruction + sizeof(OPCODE));
			inst_data->size			= sizeof(OPCODE) + sizeof(BYTE);
			inst_data->databus		= BUS_BYTE;
			return TRUE;
		}
		inst_data->type1			= TYPE_IMM32;
		inst_data->op132			= *(PDWORD)((DWORD_PTR)inst_data->instruction + sizeof(OPCODE));
		inst_data->size				= sizeof(OPCODE) + sizeof(DWORD);
		inst_data->databus			= BUS_DWORD;
		return TRUE;
	}

	if (*(PBYTE)((DWORD_PTR)inst_data->instruction + sizeof(PREFIX)) == 0x8c) {
		// Segment instruction: mov immptr, segment... mov word ptr [0x12345678], ss
		// Always 16-bit
		inst_data->opcode			= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
		inst_data->modrm			= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size + sizeof(OPCODE));
		inst_data->size				= inst_data->size + sizeof(OPCODE) + sizeof(MODRM);
		inst_data->type1			= TYPE_IMMPTR;
		inst_data->op132			= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
		inst_data->size				+= sizeof(DWORD);
		inst_data->type2			= TYPE_REG;
		inst_data->reg2				= seg_register_list[(inst_data->modrm & 0x38) >> 3];
		inst_data->command			= C_MOV;
		return TRUE;
	}

	// int 3
	if (*(PBYTE)inst_data->instruction	== 0xcc) {
		inst_data->command			= C_INT3;
		inst_data->size				= 1;
		return TRUE;
	}

	// 0xff group INC Ev, DEC Ev, Call Ev, Jmp Ev, Push Ev
	/*
	if (*(PBYTE)inst_data->instruction == 0xff) {
		inst_data->opcode	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
		inst_data->modrm	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size + sizeof(OPCODE));
		inst_data->command	= gp_commands[(inst_data->modrm & 0x38) >> 3];
		/*
		switch ((*(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size + sizeof(OPCODE)) & 0x38) >> 3)
		{
		case 0:
			inst_data->co


		default:
			return FALSE;
		}
	}*/

	return FALSE;
}

// decode conditional jumps
static ERROR_CODE decode_cond_jump(Px86_INSTRUCTION inst_data)
{

	if (inst_data->opcode_prefix == 0x0f) {
		//DWORD offset
		inst_data->jmp_offset	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
		inst_data->size			+= sizeof(DWORD);
		inst_data->command		= cond_jump_commands[((inst_data->opcode) & 0x0f) / 2];
	} else {
		//BYTE offset
		inst_data->jmp_offset	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
		inst_data->size			+= sizeof(BYTE);
		inst_data->command		= cond_jump_commands[((inst_data->opcode) & 0x0f) / 2];
	}

	// Determine if negated
	if (inst_data->opcode & 1) {
		// Negated
		inst_data->jmp_type		= JUMP_COND_NEG;
	} else {
		// Not negated
		inst_data->jmp_type		= JUMP_COND;
	}

	return TRUE;
}

// decoding modrm for non-encoded commands (xor dl, cl)
static ERROR_CODE decode_modrm(Px86_INSTRUCTION inst_data, DWORD type)
{

	if (inst_data->modrm == 0) {
		//Standard modrm (aka there isn't a 16-bit prefix
		inst_data->modrm		= *(PBYTE)((DWORD_PTR)inst_data->instruction + sizeof(OPCODE));
	}
	

	if (type == MODRM_NOTENCODED) {
		goto modrm_nonencoded;
	}

	// databus
	switch (inst_data->opcode & 1)
	{
	case 0:
		inst_data->databus	= BUS_BYTE;
		break;
	case 1:
		if (inst_data->prefix[0] != PREFIX_OPERAND) {
			inst_data->databus	= BUS_DWORD;
		} else {
			inst_data->databus	= BUS_WORD;
		}
		break;
	}

	// special mov instruction 0xc6 0xc7
	if ((inst_data->opcode & 0xfe) == 0xc6) {
		if ((inst_data->modrm & 0x7) == 0x4) {
			// SIB in dst
			inst_data->sib	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size++;
			decode_sib(inst_data, SIB_STANDARD);
		} else {
			// No sib
			if ((inst_data->modrm & 0x7) == 0x5) {
				// Modrm indicates either a [reg], [reg + byte], [reg + dword] or reg******

				switch ((inst_data->modrm & 0xc0) >> 6)
				{
				case 0x0:
					inst_data->type1	= TYPE_IMMPTR;
					inst_data->op132	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
					inst_data->size		+= sizeof(DWORD);
					break;
				case 0x1:
					inst_data->type1	= TYPE_REGPTR;
					inst_data->reg1		= REG_EBP;
					inst_data->offset1	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
					inst_data->size		+= sizeof(BYTE);
					break;
				case 0x2:
					NOP;
					break;
				case 0x3:
					NOP;
					break;
				}
			} else {
				NOP;
			}

		}
		switch (inst_data->opcode & 1) 
		{
		case 0: //imm8
			inst_data->type2	= TYPE_IMM8;
			inst_data->op28		= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size		+= sizeof(BYTE);
			break;
		case 1: //imm32
			inst_data->type2	= TYPE_IMM32;
			inst_data->op232	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size		+= sizeof(DWORD);
		}
		return TRUE;
	}

	// operands
	if ((inst_data->opcode & 0x3) >> 1) {
		// xor ebx, ecx; xor eax, [edx]=> either reg, reg; reg, [reg]
modrm_nonencoded:	
		switch ((inst_data->modrm & 0xc0) >> 6)
		{
		case 0x0: // reg, [reg]
			inst_data->type1	= TYPE_REG;
			inst_data->reg1		= modrm_regs[(inst_data->modrm & 0x38) >> 3];

			if ((inst_data->modrm & 0x7) == 0x5) {
				// last 3 bits of mod rm is 101, implying that there is a hardcoded address, rather than register
				inst_data->type2	= TYPE_IMMPTR;
				inst_data->op232	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
				inst_data->size		+= sizeof(DWORD);
			} else {
				inst_data->type2	= TYPE_REGPTR;
				inst_data->reg2		= modrm_regs[inst_data->modrm & 0x7];
			}
			break;
		case 0x1: // reg, [reg + byte]
			inst_data->type1	= TYPE_REG;
			inst_data->reg1		= modrm_regs[(inst_data->modrm & 0x38) >> 3];
			if ((inst_data->modrm & 0x7) == 0x4) {
				// operand is a SIB byte
				inst_data->sib	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
				inst_data->size++;
				decode_sib(inst_data, SIB_NOTENCODED);
				break;
			}
			inst_data->type2	= TYPE_REGPTR;
			inst_data->reg2		= modrm_regs[inst_data->modrm & 0x7];
			inst_data->offset2	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size		+= sizeof(BYTE);
			break;
		case 0x2: // reg, [reg + dword]
			inst_data->type1	= TYPE_REG;
			inst_data->reg1		= modrm_regs[(inst_data->modrm & 0x38) >> 3];
			if ((inst_data->modrm & 0x7) == 0x4) {
				inst_data->sib	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
				inst_data->size++;
				decode_sib(inst_data, SIB_NOTENCODED);
				break;
			}
			inst_data->type2	= TYPE_REGPTR;
			inst_data->reg2		= modrm_regs[inst_data->modrm & 0x7];
			inst_data->offset2	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size		+= sizeof(DWORD);
			break;
		case 0x3: // reg, reg
			inst_data->type1	= TYPE_REG;
			inst_data->type2	= TYPE_REG;
			inst_data->reg1		= modrm_regs[(inst_data->modrm & 0x38) >> 3];
			inst_data->reg2		= modrm_regs[inst_data->modrm & 0x7];
			break;
		}
	} else {
		// xor [eax], esp=> [reg], reg or reg, reg
modrm_regptr_reg:
		switch ((inst_data->modrm & 0xc0) >> 6) 
		{
		case 0x0:
			if ((inst_data->modrm & 0x7) == 0x5) {
				// dst is an immptr
				inst_data->type1	= TYPE_IMMPTR;
				inst_data->op132	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
				inst_data->size		+= sizeof(DWORD);
				inst_data->type2	= TYPE_REG;
				inst_data->reg2		= modrm_regs[(inst_data->modrm & 0x38) >> 3];
				break;
			}
			inst_data->type1		= TYPE_REGPTR;
			inst_data->reg1			= modrm_regs[inst_data->modrm & 0x7];
			inst_data->type2		= TYPE_REG;
			inst_data->reg2			= modrm_regs[(inst_data->modrm & 0x38) >> 3];
			break;
		case 0x1:
			// [reg + byte], reg

			// [rbp +- byte], reg
			inst_data->type2	= TYPE_REG;
			inst_data->reg2		= modrm_regs[(inst_data->modrm & 0x38) >> 3];
			inst_data->type1	= TYPE_REGPTR;
			
			if ((inst_data->modrm & 0x7) == 0x4) {
				// operand is a SIB byte
				inst_data->sib	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
				inst_data->size++;
				decode_sib(inst_data, SIB_STANDARD);
				//break;
			} else {
				inst_data->reg1		= modrm_regs[inst_data->modrm & 0x7];
				if (*(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size) & 0x80) {
					// negative
					inst_data->offset1	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size) | 0xffffff00;
				} else {
					// positive
					inst_data->offset1	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
				}
				inst_data->size		+= sizeof(BYTE);
			}

			break;
		case 0x2:
			// [reg + dword], reg
			inst_data->type2	= TYPE_REG;
			inst_data->reg2		= modrm_regs[(inst_data->modrm & 0x38) >> 3];
			if ((inst_data->modrm & 0x7) == 0x4) {
				// There is an extended SIB byte. mov [esp + 0x1234], eax
				inst_data->sib	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
				inst_data->size++;
				decode_sib(inst_data, SIB_STANDARD);
			} else {
				// No SIB byte
				inst_data->reg1	= modrm_regs[inst_data->modrm & 0x7];
				inst_data->type1= TYPE_REGPTR;
				inst_data->offset1	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
				inst_data->size	+= sizeof(DWORD);
			}
			break;
		case 0x3:
			// reg, reg
			inst_data->type1	= TYPE_REG;
			inst_data->type2	= TYPE_REG;
			inst_data->reg1		= modrm_regs[(inst_data->modrm & 0x38) >> 3];
			inst_data->reg2		= modrm_regs[inst_data->modrm & 0x7];
			break;
		}
	}

	return TRUE;
}

static VOID decode_sib(Px86_INSTRUCTION inst_data, DWORD type)
{

	// generally used for instructions like LEA, where the reg->reg direction is nonencoded into the modrm byte
	if (type == SIB_NOTENCODED) {
		goto sib_nonencoded;
	}

	// Check if this is a mov [esp + imm], reg instruction.
	// If so, then the index will be 1, and SIB is not required
	if (	!(inst_data->sib & 0xc0) &&
			(((inst_data->sib & 0x38) >> 3) == 0x4) &&
			((inst_data->sib & 0x7) == 0x4)) {
		if ((inst_data->modrm & 0x7) == 0x4) {
			// SIB byte is in the dst (1), determine the size of offset
			switch ((inst_data->modrm & 0xc0) >> 6)
			{
			case 0: // no offset
				inst_data->type1	= TYPE_REGPTR;
				inst_data->reg1		= REG_ESP;
				break;
			case 1: // [sib + sbyte]
				inst_data->type1	= TYPE_REGPTR;
				inst_data->reg1		= REG_ESP;
				inst_data->offset1	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
				inst_data->size		+= sizeof(BYTE);
				break;
			case 2: // [sib + sdword]
				inst_data->type1	= TYPE_REGPTR;
				inst_data->reg1		= REG_ESP;
				inst_data->offset1	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
				inst_data->size		+= sizeof(DWORD);		
				break;
			}
		} else {
			// SIB byte is in the src (2)
sib_nonencoded:
			switch ((inst_data->modrm & 0xc0) >> 6)
			{
			case 0: // no offset
				NOP;
				break;
			case 1: // [sib + sbyte]
				inst_data->type2	= TYPE_REGPTR;
				inst_data->reg2		= REG_ESP;
				inst_data->offset2	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
				inst_data->size		+= sizeof(BYTE);
				break;
			case 2: // [sib + sdword]
				inst_data->type2	= TYPE_REGPTR;
				inst_data->reg2		= REG_ESP;
				inst_data->offset2	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
				inst_data->size		+= sizeof(DWORD);		
				break;
			}
		}
		return;
	}

	return;
}

// no modrm, might include imm, or register operations encoded: nop, stosb, int, etc
static ERROR_CODE decode_simple_instruction(Px86_INSTRUCTION inst_data, UINT command)
{
	inst_data->command	= single_opcode_nomodrm_commands[command][PARM_COMM];
	inst_data->opcode	= single_opcode_nomodrm_commands[command][PARM_OPCODE];

	// dst operand
	if (single_opcode_nomodrm_commands[command][PARM_TYPEDST] != TYPE_NONE) {
		switch (single_opcode_nomodrm_commands[command][PARM_TYPEDST])
		{
		case TYPE_REG8:
			inst_data->type1	= TYPE_REG;
			inst_data->reg1		= single_opcode_nomodrm_commands[command][PARM_DST];
			inst_data->databus	= single_opcode_nomodrm_commands[command][PARM_BUS];
			break;

		case TYPE_REG32:
			inst_data->type1	= TYPE_REG;
			inst_data->reg1		= single_opcode_nomodrm_commands[command][PARM_DST];
			inst_data->databus	= single_opcode_nomodrm_commands[command][PARM_BUS];
			break;
		case TYPE_IMM8:
			inst_data->type1	= TYPE_IMM8;
			inst_data->op18		= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->databus	= single_opcode_nomodrm_commands[command][PARM_BUS];
			inst_data->size		+= sizeof(BYTE);
			break;
		case TYPE_IMM32:
			inst_data->type1	= TYPE_IMM32;
			inst_data->op132	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size		+= sizeof(DWORD);
			inst_data->databus	= single_opcode_nomodrm_commands[command][PARM_BUS];
			break;
		case TYPE_IMMPTR:
			inst_data->type1	= TYPE_IMMPTR;
			inst_data->op132	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size		+= sizeof(DWORD);
			inst_data->databus	= single_opcode_nomodrm_commands[command][PARM_BUS];
			break;
		case TYPE_IMM16:
			inst_data->type1	= TYPE_IMM16;
			inst_data->op116	= *(PWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size		+= sizeof(WORD);
			inst_data->databus	= single_opcode_nomodrm_commands[command][PARM_BUS];
			break;
		default:
			return FALSE;
		}
	}

	// src operand
	if (single_opcode_nomodrm_commands[command][PARM_TYPESRC] != TYPE_NONE) {
		switch (single_opcode_nomodrm_commands[command][PARM_TYPESRC])
		{
		case TYPE_REG8:
			inst_data->type2	= TYPE_REG;
			inst_data->reg2		= single_opcode_nomodrm_commands[command][PARM_SRC];
			break;
		case TYPE_REG32:
			inst_data->type2	= TYPE_REG;
			inst_data->reg2		= single_opcode_nomodrm_commands[command][PARM_SRC];
			break;
		case TYPE_IMM8:
			inst_data->type2	= TYPE_IMM8;
			inst_data->op28		= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size		+= sizeof(BYTE);
			break;
		case TYPE_IMM32:
			inst_data->type2	= TYPE_IMM32;
			inst_data->op232	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size		+= sizeof(DWORD);
			break;
		case TYPE_IMMPTR:
			inst_data->type2	= single_opcode_nomodrm_commands[command][PARM_TYPESRC];
			inst_data->op232	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size		+= sizeof(DWORD);
			break;
		default:
			return FALSE;
		}
	}

	return TRUE;
}

// 0x80 groups, contain a modrm (encoded command) with either imm, [reg] or reg operand
static ERROR_CODE decode_group(Px86_INSTRUCTION inst_data)
{

	if (inst_data->modrm == 0) {
		//inst_data->opcode	= *(PBYTE)inst_data->instruction;
		inst_data->modrm	= *(PBYTE)((DWORD_PTR)inst_data->instruction + sizeof(OPCODE));
	}
	inst_data->size			+= sizeof(BYTE) * 2;

	// 0xff group
	if (inst_data->opcode == 0xff) {
		NOP;
	}

	// Command
	if (inst_data->opcode != 0x8f) {

		switch (inst_data->opcode & 0xf0)
		{
		case 0x80:
			inst_data->command = gp_commands[0][(inst_data->modrm & 0x38) >> 3];
			break;
		case 0xc0: //rol, ror, rcl, rcr, etc [Eb/Ev, Ib] NOTE: constant is imm8 only
		case 0xd0: //rol, ror, rcl, rcr, etc [Eb/Ev, 1 (imm)]
			inst_data->command = gp_commands[1][(inst_data->modrm & 0x38) >> 3];
			decode_group_operands(inst_data, GROUP_IMM8_OR_CONST);
			return TRUE;
		default:
			if ((inst_data->opcode & 0xfe) == 0xf6) {
				inst_data->command = gp_commands[2][(inst_data->modrm & 0x38) >> 3];
			} else if (inst_data->opcode == 0xff) {
				// INC, DEC, CALL Ev, CALL Mp, JMP Ev, JMP Mp, PUSH Ev
				inst_data->command = gp_commands[3][(inst_data->modrm & 0x38) >> 3];
				decode_group_operands(inst_data, GROUP_SINGLE);
				return TRUE;
			} else {
				return FALSE;
			}
		}
	} else {
		// this is a Pop Ev (0x8f) instruction);
		inst_data->command	= C_POP;
	}

	// Operands
	decode_group_operands(inst_data, GROUP_STANDARD);

	return TRUE;
}

// Decodes the group opcode operands
static VOID decode_group_operands(Px86_INSTRUCTION inst_data, DWORD type)
{
	ERROR_CODE			status;

	if (type == GROUP_IMM8_OR_CONST) {
		inst_data->type1	= TYPE_REG;
		inst_data->type2	= TYPE_IMM8;
		if (inst_data->opcode & 1) {
			// 32-bit
			inst_data->databus = BUS_DWORD;
		} else {
			inst_data->databus = BUS_BYTE;
		}

		// Is this a sal Eb/Ev, Ib instruction?
		if ((inst_data->opcode & 0xf0) == 0xc0) {
			inst_data->op28	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size++;
		} 

		// Is this a sal Eb/Ev, 1 instruction?
		if ((inst_data->opcode & 0xf0) == 0xd0) {
			inst_data->op28		= 1;
		}

		decode_group_register(inst_data);

		return;
	}

	switch (inst_data->opcode & 0x03) 
	{
	case 0: //Eb, Ib (8-bit)
		inst_data->databus	= BUS_BYTE;
		if ((inst_data->modrm & 0x7)== 0x5) {
			// dst is an address
			inst_data->type1	= TYPE_IMMPTR;
			inst_data->op132	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
			inst_data->size		+= sizeof(DWORD);
		} else {
			decode_group_register(inst_data);
		}

		inst_data->type2	= TYPE_IMM8;
		inst_data->op28		= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
		inst_data->size		+= sizeof(BYTE);

		break;
	case 1: //Ev, Iz (32-bit)
		decode_group_register(inst_data);
		inst_data->databus	= BUS_DWORD;
		inst_data->type2	= TYPE_IMM32;
		inst_data->op232	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
		inst_data->size		+= sizeof(DWORD);
		break;
	case 2: //Eb, Ib*
		NOP;
		break;
	case 3: //Ev, Ib
		if (type == GROUP_SINGLE) {
			// single operand groups, CALL reg, JMP reg
			decode_group_register(inst_data);
			inst_data->databus = BUS_DWORD;
			break;
		}
		status = decode_group_register(inst_data);
		if (status == GROUP_ALREADY_ENCODED) {
			break;
		}

		// It may belong to NOT, NEG, etc (0xf6/7)
		if (inst_data->opcode == 0xf6) {
			inst_data->databus = BUS_BYTE;
			return;
		} else if (inst_data->opcode == 0xf7) {
			inst_data->databus = BUS_DWORD;
			return;
		}

		//inst_data->type1	= TYPE_REG;
		//inst_data->reg1		= modrm_regs[inst_data->modrm & 0x7];
		inst_data->databus	= BUS_BYTE;
		inst_data->type2	= TYPE_IMM8;
		inst_data->op28		= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
		inst_data->size		+= sizeof(BYTE);
		break;
	}

	return;
}

// Decodes the first register operand in group opcodes like sub [edx], 218 (812a) in modrm
static ERROR_CODE decode_group_register(Px86_INSTRUCTION inst_data)
{

	// Check if it's memory encoded
	if (((inst_data->modrm & 0x7) == 0x5) && ((inst_data->modrm & 0xc0) == 0)) {
		inst_data->type1	= TYPE_IMMPTR;
		inst_data->op132	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
		inst_data->size		+= sizeof(DWORD);
		inst_data->databus	= BUS_DWORD;
		if (inst_data->opcode	== 0x8f) {
			return GROUP_ALREADY_ENCODED;
		} else {
			return 0;
		}
	}

	switch ((inst_data->modrm & 0xc0) >> 6)
	{
	case 00:
		inst_data->type1	= TYPE_REG;
		inst_data->reg1		= modrm_regs[inst_data->modrm & 0x7];
		break;
	case 01:
		inst_data->type1	= TYPE_REGPTR;
		inst_data->reg1		= modrm_regs[inst_data->modrm & 0x7];
		inst_data->offset1	= *(PBYTE)((DWORD_PTR)inst_data->instruction + inst_data->size);
		inst_data->size		+= sizeof(BYTE);
		break;
	case 02:
		inst_data->type1	= TYPE_REGPTR;
		inst_data->reg1		= modrm_regs[inst_data->modrm & 0x7];
		inst_data->offset1	= *(PDWORD)((DWORD_PTR)inst_data->instruction + inst_data->size);
		inst_data->size		+= sizeof(DWORD);
		break;
	case 03:
		inst_data->type1	= TYPE_REG;
		inst_data->reg1		= modrm_regs[inst_data->modrm & 0x07];

		break;
	}

	return 0;
}

// Returns a pointer to the original PE buffer
static ERROR_CODE isolate_code_segment(PDWORD pe, PDWORD *code, PUINT size)
{
	PIMAGE_DOS_HEADER				dos_header;
	PIMAGE_NT_HEADERS				nt_headers;
	PIMAGE_SECTION_HEADER			section_header;

	INT								i;

	dos_header = (PIMAGE_DOS_HEADER)pe;
	nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)pe + dos_header->e_lfanew);

	section_header = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt_headers);

	// Determine executable segment
	for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {

		if (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			break;
		}

		section_header++;
	}
	if (i == nt_headers->FileHeader.NumberOfSections) {
		return FALSE;
	}

	// Set pointers
	*code		= (PDWORD)((DWORD_PTR)pe + section_header->PointerToRawData);
	*size		= (UINT)section_header->SizeOfRawData;

	return TRUE;
}

static VOID print_instruction(Px86_INSTRUCTION inst_data, UINT offset)
{
	CHAR	output[1024]			= {0};
	CHAR	encoded_bytes[33]		= {0};
	CHAR	operands[1024]			= {0};

	PCHAR	ptr;

	INT		tmp;

	UINT	i;

	for (i = 0; i < (inst_data->size); i++) {
		get_byte_hex(	*(PBYTE)((DWORD_PTR)inst_data->instruction + i),
						&encoded_bytes[i * 2],
						&encoded_bytes[(i * 2) + 1]);
	}

	// fill with spaces
	tmp = strlen(encoded_bytes);
	if (tmp < 16) {
		ptr = encoded_bytes;
		while (*ptr != 0) {
			ptr++;
		}
		for (i = 0; i < (16 - tmp); i++) {
			*ptr = ' ';
			ptr++;
		}
	}

	// Int3?
	if (inst_data->command == C_INT3) {
		printf("0x%08x[0x%08x] CC int 3\n", inst_data->instruction, offset);
		return;
	}

	// is this a jump of any sort?
	if (inst_data->jmp_type != 0) {
		switch (inst_data->jmp_type)
		{
		case JUMP_COND:
			_snprintf(output, sizeof(output), "0x%08x[0x%08x] %s %s 0x%08x [%x]\n",
															inst_data->instruction,
															offset,
															encoded_bytes,
															command_list[inst_data->command],
															inst_data->jmp_offset);
			break;
		case JUMP_COND_NEG:
			_snprintf(output, sizeof(output), "0x%08x[0x%08x] %s ~%s 0x%08x [%x]\n",
															inst_data->instruction,
															offset,
															encoded_bytes,
															command_list[inst_data->command],
															inst_data->jmp_offset);
		case JUMP_NONCOND:
			break;
		}

		printf(output);
		return;
	}

	// Is this a segment register instruction
	if (inst_data->opcode == 0x8c) {
		_snprintf(operands, sizeof(operands), "[0x%08x], %s", inst_data->op132, segment_registers[inst_data->reg2]);
		goto print_inst_end;
	}

	// dst
	switch (inst_data->databus) 
	{
	case BUS_DWORD:
		switch (inst_data->type1) 
		{
		case TYPE_REG:
			_snprintf(operands, sizeof(operands), "%s", register_list32[inst_data->reg1]);
			break;
		case TYPE_REGPTR:
			if (inst_data->offset1 != 0) {
				// There exists a register offset [reg + imm32]
				if ((inst_data->offset1 & 0x80) >> 7) {
					_snprintf(operands, sizeof(operands), "[%s - 0x%08x]", register_list32[inst_data->reg1], ~inst_data->offset1 + 1);
				} else {
					_snprintf(operands, sizeof(operands), "[%s + 0x%08x]", register_list32[inst_data->reg1], inst_data->offset1);
				}
			} else {
				// no offset [reg]
				_snprintf(operands, sizeof(operands), "[%s]", register_list32[inst_data->reg1]);
			}
			break;
		case TYPE_IMM32:
			_snprintf(operands, sizeof(operands), "0x%08x", inst_data->op132);
			break;
		case TYPE_IMMPTR:
			_snprintf(operands, sizeof(operands), "[0x%08x]", inst_data->op132);
			break;
		}
		break;
	case BUS_BYTE:
		switch (inst_data->type1) 
		{
		case TYPE_REG:
			_snprintf(operands, sizeof(operands), "%s", register_list8[inst_data->reg1]);
			break;
		case TYPE_REGPTR:
			if (inst_data->offset1 != 0) {
				// There exists a register offset [reg + imm32]
				if ((inst_data->offset1 & 0x80) >> 7) {
					_snprintf(operands, sizeof(operands), "[%s - 0x%08x]", register_list32[inst_data->reg1], ~inst_data->offset1 + 1);
				} else {
					_snprintf(operands, sizeof(operands), "[%s + 0x%08x]", register_list32[inst_data->reg1], inst_data->offset1);
				}
			}
			break;
		case TYPE_IMMPTR:
			_snprintf(operands, sizeof(operands), "[0x%08x]", inst_data->op132);
			break;
		case TYPE_IMM8:
			_snprintf(operands, sizeof(operands), "0x%02x", inst_data->op18);
			break;
		}
		break;
	case BUS_WORD:
		switch (inst_data->type1)
		{
		case TYPE_REG:
			_snprintf(operands, sizeof(operands), "%s", register_list16[inst_data->reg1]);
			break;
		case TYPE_REGPTR:
			if (inst_data->offset1 != 0) {
				// There exists a register offset [reg + imm32]
				if ((inst_data->offset1 & 0x80) >> 7) {
					_snprintf(operands, sizeof(operands), "[%s - 0x%08x]", register_list16[inst_data->reg1], ~inst_data->offset1 + 1);
				} else {
					_snprintf(operands, sizeof(operands), "[%s + 0x%08x]", register_list16[inst_data->reg1], inst_data->offset1);
				}
			} else {
				// no offset [reg]
				_snprintf(operands, sizeof(operands), "[%s]", register_list16[inst_data->reg1]);
			}
			break;
		case TYPE_IMM32:
			_snprintf(operands, sizeof(operands), "0x%08x", inst_data->op132);
			break;
		case TYPE_IMMPTR:
			_snprintf(operands, sizeof(operands), "[0x%08x]", inst_data->op132);
			break;
		}

	}

	// src
	switch (inst_data->databus) {
	case BUS_DWORD:
		switch (inst_data->type2) {
		case TYPE_REG:
			_snprintf(operands, sizeof(operands), "%s, %s", operands, register_list32[inst_data->reg2]);
			break;
		case TYPE_IMM32:
			_snprintf(operands, sizeof(operands), "%s, 0x%08x", operands, inst_data->op232);
			break;
		case TYPE_IMMPTR:
			_snprintf(operands, sizeof(operands), "%s, [0x%08x]", operands, inst_data->op232);
			break;
		case TYPE_REGPTR:
			if (inst_data->offset2 != 0) {
				// There exists a register offset [reg + imm32]
				if ((inst_data->offset2 & 0x80) >> 7) {
					_snprintf(operands, sizeof(operands), "%s, [%s - 0x%08x]", operands, register_list32[inst_data->reg2], ~inst_data->offset2 + 1);
				} else {
					_snprintf(operands, sizeof(operands), "%s, [%s + 0x%08x]", operands, register_list32[inst_data->reg2], inst_data->offset2);
				}
			} else {
				// something like reg, [ebp]
				_snprintf(operands, sizeof(operands), "%s, [%s]", operands, register_list32[inst_data->reg2]);
			}
			break;
		case TYPE_IMM8:
			_snprintf(operands, sizeof(operands), "%s, 0x%02x", operands, inst_data->op28);
			break;
		}
		break;
	case BUS_BYTE:
		switch (inst_data->type2)
		{
		case TYPE_REG:
			_snprintf(operands, sizeof(operands), "%s, %s", operands, register_list8[inst_data->reg2]);
			break;
		case TYPE_IMM32:
			_snprintf(operands, sizeof(operands), "%s, 0x%08x", operands, inst_data->op232);
			break;
		case TYPE_IMMPTR:
			_snprintf(operands, sizeof(operands), "%s, [0x%08x]", operands, inst_data->op232);
			break;
		case TYPE_IMM8:
			_snprintf(operands, sizeof(operands), "%s, 0x%02x", operands, inst_data->op28);
			break;
		case TYPE_REGPTR:
			_snprintf(operands, sizeof(operands), "%s, [%s]", operands, register_list32[inst_data->reg2]);
			break;
		}
		break;
	case BUS_WORD:
		switch (inst_data->type2) 
		{
		case TYPE_REG:
			_snprintf(operands, sizeof(operands), "%s, %s", operands, register_list16[inst_data->reg2]);
			break;
		case TYPE_IMM32:
			_snprintf(operands, sizeof(operands), "%s, 0x%08x", operands, inst_data->op232);
			break;
		case TYPE_IMMPTR:
			_snprintf(operands, sizeof(operands), "%s, [0x%08x]", operands, inst_data->op232);
			break;
		case TYPE_REGPTR:
			if (inst_data->offset2 != 0) {
				// There exists a register offset [reg + imm32]
				if ((inst_data->offset2 & 0x80) >> 7) {
					_snprintf(operands, sizeof(operands), "%s, [%s - 0x%08x]", operands, register_list16[inst_data->reg2], ~inst_data->offset2 + 1);
				} else {
					_snprintf(operands, sizeof(operands), "%s, [%s + 0x%08x]", operands, register_list16[inst_data->reg2], inst_data->offset2);
				}
			}
			break;
		case TYPE_IMM8:
			_snprintf(operands, sizeof(operands), "%s, 0x%02x", operands, inst_data->op28);
			break;
		}
		break;
	}

	// any prefix?
print_inst_end:
	if (inst_data->prefix[0] != 0) {
		for (i = 0; i < sizeof(prefix_list); i++) {
			if (prefix_list[i] == inst_data->prefix[0]) {
				_snprintf(output, sizeof(output), "0x%08x[0x%08x] %s %s:%s %s\n",
																	inst_data->instruction, 
																	offset,
																	encoded_bytes, 
																	prefix_list_names[i],
																	command_list[inst_data->command],
																	operands,
																	offset);
				printf("%s", output);
				return;
			}
		}
	}

	_snprintf(output, sizeof(output), "0x%08x[0x%08x] %s %s %s\n",
														inst_data->instruction, 
														offset,
														encoded_bytes, 
														command_list[inst_data->command],
														operands,
														offset);

	printf("%s", output);

	return;
}