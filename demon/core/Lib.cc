#include "Common.h"

static size_t encode_utf8( unsigned int codepoint, char * buffer ) {
	if (codepoint <= 0x7F) {
		if (buffer) * buffer = (char) codepoint;
		return 1;
	} else if (codepoint <= 0x7FF) {
		if (buffer) {
			buffer[0] = (char) (0xC0 | (codepoint >> 6));
			buffer[1] = (char) (0x80 | (codepoint & 0x3F));
		}
		return 2;
	} else if (codepoint <= 0xFFFF) {
		if (buffer) {
			buffer[0] = (char) (0xE0 | (codepoint >> 12));
			buffer[1] = (char) (0x80 | ((codepoint >> 6) & 0x3F));
			buffer[2] = (char) (0x80 | (codepoint & 0x3F));
		}
		return 3;
	} else if (codepoint <= 0x10FFFF) {
		if (buffer) {
			buffer[0] = (char) (0xF0 | (codepoint >> 18));
			buffer[1] = (char) (0x80 | ((codepoint >> 12) & 0x3F));
			buffer[2] = (char) (0x80 | ((codepoint >> 6) & 0x3F));
			buffer[3] = (char) (0x80 | (codepoint & 0x3F));
		}
		return 4;
	}
	return 0;
}

size_t WideCharToMultiByte( const wchar_t * wideStr, size_t wideLen, char * multiByteStr, size_t multiByteSize ) {
	if (!wideStr) return 0;

	size_t totalBytes = 0;
	for (size_t i = 0; i < wideLen; ++i) {
		unsigned int codepoint;

		if (wideStr[i] >= 0xD800 && wideStr[i] <= 0xDBFF) {
			if (i + 1 < wideLen && wideStr[i + 1] >= 0xDC00 && wideStr[i + 1] <= 0xDFFF) {
				codepoint = 0x10000 + (((wideStr[i] - 0xD800) << 10) | (wideStr[i + 1] - 0xDC00));
				++i;
			} else {
				return 0;
			}
		} else {
			codepoint = wideStr[i];
		}

		size_t bytes = encode_utf8( codepoint, multiByteStr ? multiByteStr + totalBytes : NULL );
		if (totalBytes + bytes > multiByteSize && multiByteStr) {
			return 0;
		}
		totalBytes += bytes;
	}

	if (multiByteStr && totalBytes < multiByteSize) {
		multiByteStr[totalBytes] = '\0';
	}

	return totalBytes;
}

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
				pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length / 2, baseDllName, MAX_PATH
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

	return (FARPROC) 0xdeadbeef;
};