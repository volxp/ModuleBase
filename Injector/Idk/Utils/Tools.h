#pragma once
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <Psapi.h>
#include "ntdlldefs.h"

static const char* basic_chars = "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM<>,./?:;'\"|\\{}-_=+!@#$%^&*()[]~ \n";

SYSTEM_PROCESS_INFORMATION * FindProcessByModuleName(const wchar_t * modname);
MODULEINFO FindModuleByNameInProcess(HANDLE process,const wchar_t * modname);
ULONG_PTR PFindData(const BYTE* data, ULONG_PTR dsize, ULONG_PTR startpos, SIZE_T fsize, HANDLE hProcess, SIZE_T bufsize);

extern "C" DWORD GetCurrentTID();
extern "C" void Capture(...);

extern "C" NTSTATUS NtQueryVirtualMemoryInline(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);
extern "C" NTSTATUS NtContuneInline(PCONTEXT context,BOOL a);
extern "C" NTSTATUS NtProtectVirtualMemoryInline(    _In_ HANDLE ProcessHandle,    _Inout_ PVOID* BaseAddress,    _Inout_ PSIZE_T RegionSize,    _In_ ULONG NewProtect,    _Out_ PULONG OldProtect);