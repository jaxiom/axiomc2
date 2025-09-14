#ifndef LOADER_H
#define LOADER_H

#include <windows.h>

// Retrieves the address of an exported function from a module.
FARPROC GetProcAddressR(HMODULE hModule, LPCSTR lpProcName);

// Determines if a DLL loaded at the given address is a 64-bit module.
BOOL Is64BitDLL(UINT_PTR uiLibraryAddress);

// Reads the entire contents of the file specified by 'filename'.
// On success, allocates memory for the file data (caller must free it) and sets 'size' to the file size.
// Returns non-zero on success.
DWORD GetFileContents(LPCSTR filename, LPSTR *data, DWORD &size);

// Computes a hash for a function name. This is used to identify exported functions.
DWORD HashFunctionName(LPSTR name);

// Converts the given DLL (in memory) to shellcode using the sRDI technique.
BOOL ConvertToShellcode(
	LPVOID inBytes,
	DWORD length,
	DWORD userFunction,
	LPVOID userData,
	DWORD userLength,
	DWORD flags,
	LPSTR &outBytes,
	DWORD &outLength
);

#endif // LOADER_H
