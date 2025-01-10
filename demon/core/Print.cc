#include "Common.h"

#define SEED 0xDEADBEEF

extern "C" VOID printf( const char * pszFormat, ... ) {
	if (!DemonInstance.api.GetStdHandle || !DemonInstance.api.WriteFile) {
		return;
	}
	char buf[1024];
	va_list argList;
	va_start( argList, pszFormat );
	wvsprintfA( buf, pszFormat, argList );
	va_end( argList );
	DWORD done = 0;
	HANDLE hStdOut = CALL_API( GetStdHandle, STD_OUTPUT_HANDLE );
	CALL_API( WriteFile, hStdOut, buf, strlen( buf ), & done, NULL );
}
extern "C" size_t strlen( const char * str ) {
	size_t len = 0;
	while (str[len] != '\0') {
		len++;
	}
	return len;
}

