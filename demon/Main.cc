#include "Common.h"

BOOL Start( VOID ) {
	Demon demon = {0};
	InitFunc( & demon );

	PRINT( & demon, "MessageBoxA: %p", demon.api.MessageBoxA );
	CALL_API( & demon, MessageBoxA, NULL, "Hello, World!", "Hello, World!", MB_OK );

	return TRUE;
}