#ifndef DEMON_INITIALIZE_H
#define DEMON_DEMON_H

#include "Common.h"

typedef struct API {
	FARPROC GetStdHandle;
	FARPROC WriteFile;
	FARPROC MessageBoxA;
	FARPROC Sleep;
} API;

typedef struct {
	API api;
} Demon;

#define CALL_API( apiName, ... ) \
    ((decltype(&apiName))(DemonInstance.api.apiName))(__VA_ARGS__)

VOID DemonSleep( DWORD dwMilliseconds );

#endif
