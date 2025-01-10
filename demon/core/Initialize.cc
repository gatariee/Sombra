#include "Common.h"


PVOID FetchModuleHandleA( unsigned int moduleHash ) {
	PPEB pPeb = (PPEB) __readgsqword( 0x60 );
	if (!pPeb || !pPeb->Ldr) {
		return NULL;
	}
	PPEB_LDR_DATA pLdrData = pPeb->Ldr;
	LIST_ENTRY * pHead = & pLdrData->InMemoryOrderModuleList;
	LIST_ENTRY * pCurrent = pHead->Flink;
	do {
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD( pCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
		char baseDllName[MAX_PATH] = {0};
		int nameLength = WideCharToMultiByte(
				CP_ACP, 0, pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length / sizeof( WCHAR ), baseDllName
				, sizeof(baseDllName) - 1, NULL, NULL
		);

		unsigned int computedHash = Hash( baseDllName );
		if (computedHash == moduleHash) {
			return (HMODULE) pEntry->DllBase;
		}
		pCurrent = pCurrent->Flink;
	} while (pCurrent != pHead);

	return NULL;
}

FARPROC ResolveFunctionByHash( DWORD hash, unsigned int moduleHash ) {

	LPVOID hModule = FetchModuleHandleA( moduleHash );
	if (!hModule) {
		return NULL;
	}

	PIMAGE_DOS_HEADER MmDosHdr = {0};
	PIMAGE_NT_HEADERS MmNtHdr = {0};
	PIMAGE_EXPORT_DIRECTORY ExportDir = {0};
	PIMAGE_SECTION_HEADER MmSectionHdr = {0};

	MmDosHdr = (PIMAGE_DOS_HEADER) hModule;
	MmNtHdr = (PIMAGE_NT_HEADERS) ((UINT_PTR) hModule + MmDosHdr->e_lfanew);
	MmSectionHdr = IMAGE_FIRST_SECTION( MmNtHdr );

	ExportDir = (PIMAGE_EXPORT_DIRECTORY) ((UINT_PTR) hModule +
										   MmNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD * AddressOfFunctions = (DWORD *) ((UINT_PTR) hModule + ExportDir->AddressOfFunctions);
	DWORD * AddressOfNames = (DWORD *) ((UINT_PTR) hModule + ExportDir->AddressOfNames);
	WORD * AddressOfNameOrd = (WORD *) ((UINT_PTR) hModule + ExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < ExportDir->NumberOfNames; i++) {
		if (Hash( (const char *) ((UINT_PTR) hModule + AddressOfNames[i]) ) == hash) {
			return (FARPROC) ((UINT_PTR) hModule + AddressOfFunctions[AddressOfNameOrd[i]]);
		}
	}

	// Couldn't find the function, we should actually just die here but return 0xDEADBEEF for now
	return (FARPROC) 0xdeadbeef;
};

VOID InitFunc( Demon * demon ) {
	demon->api.GetStdHandle = (FARPROC) ResolveFunctionByHash( hGetStdHandle, hKernel32 );
	demon->api.WriteFile = (FARPROC) ResolveFunctionByHash( hWriteFile, hKernel32 );
	demon->api.MessageBoxA = (FARPROC) ResolveFunctionByHash( hMessageBoxA, hUser32 );
}