#ifndef DEMON_INITIALIZE_H
#define DEMON_DEMON_H

#include "Common.h"

typedef struct API {
	FARPROC GetStdHandle;
	FARPROC WriteFile;
	FARPROC MessageBoxA;
} API;

typedef struct {
	API api;
} Demon;

#define CALL_API( demon, apiName, ... ) \
    ((decltype(&apiName))((demon)->api.apiName))(__VA_ARGS__)

#endif