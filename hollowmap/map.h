#pragma once
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <winternl.h>

namespace Map {
	PVOID ExtendMap(Comm::Process &process, LPCWSTR filePath, LPCWSTR module);

	typedef LONG(__stdcall* NtCreateSection_t)(HANDLE*, ULONG, void*, LARGE_INTEGER*, ULONG, ULONG, HANDLE);
	typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
	typedef NTSTATUS(__stdcall* NtCreateTransaction_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);

	NtCreateSection_t NtCreateSection;
	NtMapViewOfSection_t NtMapViewOfSection;
	NtCreateTransaction_t NtCreateTransaction;

	bool CheckRelocRange(uint8_t* pRelocBuf, uint32_t dwRelocBufSize, uint32_t dwStartRVA, uint32_t dwEndRVA);
	void* GetPAFromRVA(uint8_t* pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, uint64_t qwRVA);
}