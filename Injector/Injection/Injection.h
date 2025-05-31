#pragma once
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <Psapi.h>

#include "ntdlldefs.h"
#include "ThreadPool.h"
#include "WorkerFactory.h"
#include "Tools.h"
#include "TPInjection.h"
#include "SyscalCaller.h"
#include "ICHooker.h"


struct INJECTION_DLL_PARAMS {
	ULONG_PTR EntryPointOffset;
	void* BaseAddr;
};

typedef struct InternalVars {
	MODULEINFO byfron;
	void* ICAddr;
	void* Injector;
	INJECTION_DLL_PARAMS dllparams;
	MEMORY_BASIC_INFORMATION InjectionHiddenMemory[256] = {};
	DWORD InjectionHiddenMemoryC = 0;
	SYSTEM_PROCESS_INFORMATION* RobloxProcessInfo;
}*PInternalVars;

extern InternalVars injection_vars;
extern MODULEINFO thismoduleinfo;

const BYTE ByfronICPattern[8] = { 0x41,0x52,0x50,0x9c,0x53,0x48,0x89,0xe3 }; //Byfron's IC pattern

typedef BOOL(*DLLMAIN)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

bool GetThisModuleInfo();

//Internal part
void InjectionICHook(ICStack* stack);
int InjectionDllCaller();

//External part
bool InjectionFindByfron(HANDLE process, PInternalVars s);
bool InjectionAllocSelf(HANDLE process, PInternalVars s, MODULEINFO thismodinfo);
bool InjectionSetupInternalPart(HANDLE process, PInternalVars s);

//tools
ULONG_PTR ConvertAddrByBase(ULONG_PTR Addr, ULONG_PTR OldBase, ULONG_PTR NewBase);
void* ConvertAddrByBase(const void* Addr, const void* OldBase, const void* NewBase);