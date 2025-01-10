#include "Common.h"

Demon DemonInstance = {0};

BOOL Start( VOID ) {
	InitFunc( & DemonInstance );
	PRINT( "MessageBoxA: %p", DemonInstance.api.MessageBoxA );
	CALL_API( MessageBoxA, NULL, "Hello, World!", "Title", MB_OK );
	return TRUE;
}