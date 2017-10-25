#include "disasm.h"

BOOL read_raw_into_buffer(	__in	LPCSTR	file_name,
							__out	PUINT	file_size,
							__out	LPVOID	*out_file)
{
	ERROR_CODE			status;

	HANDLE				handle						= INVALID_HANDLE_VALUE;
	DWORD				size_high, size_low;
	PDWORD				buffer;
	DOUBLE				size;
	INT					junk;

	handle = CreateFileA(		file_name, 
								GENERIC_READ, 
								FILE_SHARE_READ, 
								NULL, 
								OPEN_EXISTING, 
								FILE_ATTRIBUTE_NORMAL, 
								NULL);

	if (handle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	size_low		= GetFileSize(handle, &size_high);
	size			= (size_low | size_high);

	buffer			= (DWORD *)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (buffer == NULL) {
		return FALSE;
	}

	status			= ReadFile(handle, buffer, size, (LPDWORD)&junk, NULL);
	if (!status) {
		return FALSE;
	}

	CloseHandle(handle);
	*file_size	= size;
	*out_file	= buffer;

	return TRUE;
}

VOID get_byte_hex(	__in	CHAR	b,
					__out	PCHAR	ch1,
					__out	PCHAR	ch2)
{
	CCHAR nybble_chars[] = "0123456789ABCDEF";

	*ch1 = nybble_chars[ ( b >> 4 ) & 0x0F ];
	*ch2 = nybble_chars[ b & 0x0F ];

	return;
}