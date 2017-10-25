BOOL read_raw_into_buffer(	__in	LPCSTR	file_name,
							__out	PUINT	file_size,
							__out	LPVOID	*out_file);
VOID get_byte_hex(	__in	CHAR	b,
					__out	PCHAR	ch1,
					__out	PCHAR	ch2);