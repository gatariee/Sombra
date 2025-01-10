#ifndef DEMON_COMMON_H
#define DEMON_COMMON_H

#include <windows.h>
#include <ntdef.h>
#include <psapi.h>
#include <tlhelp32.h>

#include "Demon.h"
#include "Win32.h"

// stdlib
extern "C" VOID DemonPrint( const char * pszFormat, ... );
extern "C" size_t strlen( const char * str );

// dfr
#define SEED 0xdeadbeef

constexpr unsigned int crc32h_impl( const char * message, unsigned int crc, unsigned int i ) {
	return (message[i] == '\0')
		   ? ~crc
		   : crc32h_impl(
					message, ((crc ^ message[i]) >> 8) ^ ((((crc ^ message[i]) & 1) ? SEED : 0) ^
														  (((crc ^ message[i]) & 2) ? (SEED >> 1) : 0) ^
														  (((crc ^ message[i]) & 4) ? (SEED >> 2) : 0) ^
														  (((crc ^ message[i]) & 8) ? (SEED >> 3) : 0) ^
														  (((crc ^ message[i]) & 16) ? (SEED >> 4) : 0) ^
														  (((crc ^ message[i]) & 32) ? (SEED >> 5) : 0) ^
														  (((crc ^ message[i]) & 64) ? ((SEED >> 6) ^ SEED) : 0) ^
														  (((crc ^ message[i]) & 128) ? (((SEED >> 6) ^ SEED)
																  >> 1) : 0)), i + 1
			);
}

constexpr unsigned int crc32h( const char * message ) {
	return crc32h_impl( message, 0xFFFFFFFF, 0 );
}

#define Hash( x ) crc32h( x )

// DFR DLL
constexpr DWORD hKernel32 = Hash( "KERNEL32.DLL" );
constexpr DWORD hNtdll = Hash( "ntdll.dll" );
constexpr DWORD hUser32 = Hash( "USER32.dll" );

// DFR API
constexpr DWORD hGetStdHandle = Hash( "GetStdHandle" );
constexpr DWORD hWriteFile = Hash( "WriteFile" );
constexpr DWORD hMessageBoxA = Hash( "MessageBoxA" );
constexpr DWORD hSleep = Hash( "Sleep" );

#define NULL nullptr


#ifdef DEBUG
#define FILENAME (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define PRINT(fmt, ...) \
    DemonPrint("[ Debug ] %-9s -> %-8s #L%-3d - " fmt "\n", \
               __func__, FILENAME, __LINE__, ##__VA_ARGS__)
#else
#define PRINT(fmt, ...)
#endif

extern Demon DemonInstance;

BOOL Start( VOID );

FARPROC ResolveFunctionByHash( DWORD hash, unsigned int moduleHash );

#endif