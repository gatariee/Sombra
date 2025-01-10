#include "Common.h"

Demon DemonInstance = {0};

VOID InitFunc( Demon * DemonInstance ) {
	DemonInstance->api.GetStdHandle = (FARPROC) ResolveFunctionByHash( hGetStdHandle, hKernel32 );
	DemonInstance->api.WriteFile = (FARPROC) ResolveFunctionByHash( hWriteFile, hKernel32 );
	DemonInstance->api.MessageBoxA = (FARPROC) ResolveFunctionByHash( hMessageBoxA, hUser32 );
}

BOOL Start( VOID ) {
	InitFunc( & DemonInstance );
	PRINT( "APIs resolved\n" );
	CALL_API( MessageBoxA, NULL, "hi", "jess", MB_OK );
	return TRUE;
}