#include "Common.h"

Demon DemonInstance = {0};

//
// DemonMain should only be entered when DemonInstance is fully initialized.
//
BOOL DemonMain( VOID ) {
	DWORD SleepTime = 3000;
	do {
		PRINT( "Demon is going to sleep for %d milliseconds.", SleepTime );
		DemonSleep( SleepTime );
		PRINT( "Demon has woken up." );
	} while (TRUE);
}

VOID InitFunc( Demon * DemonInstance ) {
	DemonInstance->api.GetStdHandle = (FARPROC) ResolveFunctionByHash( hGetStdHandle, hKernel32 );
	DemonInstance->api.WriteFile = (FARPROC) ResolveFunctionByHash( hWriteFile, hKernel32 );
	DemonInstance->api.MessageBoxA = (FARPROC) ResolveFunctionByHash( hMessageBoxA, hUser32 );
	DemonInstance->api.Sleep = (FARPROC) ResolveFunctionByHash( hSleep, hKernel32 );
}


//
// Initialize Demon
//
BOOL Start( VOID ) {
	InitFunc( & DemonInstance );
	PRINT( "Demon initialized, beginning routine." );

	if (!DemonMain()) {
		PRINT( "DemonMain failed." );
		return FALSE;
	}

	PRINT( "Routine complete." );
	return TRUE;
}