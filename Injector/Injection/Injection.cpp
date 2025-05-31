#include "Injection.h"
#include "iostream"
#include "thread"
#include "string"
#include <sstream>
#include <string>
#include "../Update/offsets.hpp"
#include <spdlog/spdlog.h>
using namespace Offsets;
typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);



void InjectionICHook(ICStack* regs) {
	static HANDLE iclogfile = NULL;
	if (iclogfile == NULL) {
		iclogfile = CreateFileW(L"ICLog.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
		SetFilePointer(iclogfile, 0, NULL, FILE_BEGIN);
	}


		static void* KiUserCallbackDispatcher = GetProcAddress(NTDLL, "KiUserCallbackDispatcher");
		static void* KiUserApcDispatcher = GetProcAddress(NTDLL, "KiUserApcDispatcher");
		static void* KiUserExceptionDispatcher = GetProcAddress(NTDLL, "KiUserExceptionDispatcher");
		static auto RtlRestoreContext = (void (*)(PCONTEXT, PEXCEPTION_RECORD))GetProcAddress(NTDLL, "RtlRestoreContext");

		if (regs->r10 == (DWORD64)KiUserCallbackDispatcher) {
			regs->rcx = *(DWORD64*)(regs->rsp + 0x20);
			regs->returnaddr = regs->r10 + 5;
		}
		if (regs->r10 == (DWORD64)KiUserApcDispatcher) {
			regs->rcx = *(DWORD64*)(regs->rsp + 0x18);
			regs->returnaddr = regs->r10 + 5;
		}
		if (regs->r10 == (DWORD64)KiUserExceptionDispatcher) {
			PEXCEPTION_RECORD ExceptionRecord = (PEXCEPTION_RECORD)(regs->rsp + 0x4f0);
			PCONTEXT Context = (PCONTEXT)regs->rsp;

			if ((ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)) {
				MEMORY_BASIC_INFORMATION binfo = {};
				NtQueryVirtualMemoryInline((HANDLE)-1, (void*)Context->Rip, MemoryBasicInformation, &binfo, sizeof(binfo), NULL);
				NtProtectVirtualMemoryInline((HANDLE)-1, &binfo.BaseAddress, &binfo.RegionSize, PAGE_EXECUTE_READ, NULL);
				RtlRestoreContext(Context, ExceptionRecord);
			}
		}
	

	// Memory hider
	if ((regs->r10 > (ULONG_PTR)injection_vars.byfron.lpBaseOfDll) &&
		(regs->r10 < (ULONG_PTR)injection_vars.byfron.lpBaseOfDll + injection_vars.byfron.SizeOfImage)) {

		MEMORY_BASIC_INFORMATION checkinfo = {};
		DWORD stat = NtQueryVirtualMemoryInline((HANDLE)-1, (void*)regs->rsp, MemoryBasicInformation, &checkinfo, sizeof(checkinfo), NULL);
		if ((checkinfo.Type != 0) && (stat == 0)) {
			ULONG_PTR cur = regs->rsp;
			ULONG_PTR end = (ULONG_PTR)checkinfo.BaseAddress + checkinfo.RegionSize - 0x100;
			while (cur < end) {
				PMEMORY_BASIC_INFORMATION checkbi = (PMEMORY_BASIC_INFORMATION)cur;
				DWORD checkcur = 0;
				while (checkcur < injection_vars.InjectionHiddenMemoryC) {
					PMEMORY_BASIC_INFORMATION compare = &injection_vars.InjectionHiddenMemory[checkcur];
					if ((checkbi->BaseAddress == compare->BaseAddress) &&
						(checkbi->Protect == compare->Protect) &&
						(checkbi->AllocationProtect == compare->AllocationProtect)) {
						checkbi->Protect = 1;
						checkbi->AllocationProtect = 1;
						checkbi->BaseAddress = (PVOID)0;
					}
					checkcur++;
				}
				cur++;
			}
		}
	}
	regs->returnaddr = (DWORD64)injection_vars.ICAddr;
	return;
}



void LoadDlls() {
	LoadLibraryA(Dll1);
	LoadLibraryA(Dll2);
	LoadLibraryA(Dll3);
}
int InjectionDllCaller() {
	LoadDlls();


	typedef void* (__fastcall* TSetInsert)(void*, void*, void*);


	auto WhitelistPage = [](uintptr_t page) {
		void* unused = nullptr;


		uintptr_t hyperionBase = (uintptr_t)GetModuleHandleA(Hyperion);

		auto SetInsert = (TSetInsert)(hyperionBase + O_SetInsert);
		void* whitelistedPages = (void*)(hyperionBase + O_WhitelistedPages);
		
		int64_t dummy;
		int64_t* Stack = &dummy;
		Stack[5] = 0;

		uint64_t Page = page & 0xfffffffffffff000;

		Stack[-6] = (Page >> virtuals::PageShift) ^ O_PageHash;
		*(reinterpret_cast<uint8_t*>(Stack) - virtuals::kbyeshift) = ((Page >> virtuals::kbyeshift) & 0xFF) ^ BitMap::BitmapHash;
		SetInsert(whitelistedPages, &Stack[5], &Stack[-6]);

		uintptr_t bitmap = *(uintptr_t*)(hyperionBase + BitMap::Bitmap);
		uintptr_t byteOffset = (page >> BitMap::BitmapShift);
		uintptr_t bitOffset = (page >> BitMap::BitmapFieldShift) & Extraspace::IDE;

		uint8_t* cfgEntry = (uint8_t*)(bitmap + byteOffset);

		DWORD oldProtect;
		VirtualProtect(cfgEntry, 1, PAGE_READWRITE, &oldProtect);

		*cfgEntry |= (1 << bitOffset);

		VirtualProtect(cfgEntry, 1, oldProtect, &oldProtect);

		};

	uintptr_t sectionBase = (uintptr_t)GetModuleHandleA("winsta.dll") + 0x328;

	uintptr_t allocatedMemory = *(uintptr_t*)sectionBase;

	uint64_t totalSize = *(uint64_t*)(sectionBase + 0x8);

	// whitelist allocatedmemory -> allocatedmemory + totalsize
	for (uintptr_t currentPage = allocatedMemory; currentPage < allocatedMemory + totalSize; currentPage += 0x1000)
		WhitelistPage(currentPage);

	*(int*)(sectionBase + 0x10) = 1; // ready for mapping

	do {
		Sleep(1);
	} while (*(int*)(sectionBase + 0x18) != 1);

	uintptr_t entryPoint = *(uintptr_t*)(sectionBase + 0x20);

	// SEH support
	uintptr_t dllBase = *(uintptr_t*)(sectionBase + 0x28);
	uintptr_t exceptionAddress = *(uintptr_t*)(sectionBase + 0x30);
	uintptr_t exceptionSize = *(uintptr_t*)(sectionBase + 0x38);

	if (exceptionAddress != 0 && exceptionSize != 0) {
		RtlAddFunctionTable((IMAGE_RUNTIME_FUNCTION_ENTRY*)(dllBase + exceptionAddress), exceptionSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), dllBase);
	}

	BOOL(*dllMain)(HMODULE, DWORD, LPVOID) = (BOOL(*__stdcall)(HMODULE, DWORD, LPVOID))(entryPoint);

	dllMain((HMODULE)dllBase, 1, 0);


	return 0;
}


bool InjectionFindByfron(HANDLE process, PInternalVars s) {
	MODULEINFO byfron = FindModuleByNameInProcess(process, L"RobloxPlayerBeta.dll");
	if (byfron.lpBaseOfDll != 0) {
		s->byfron = byfron;
		return 1;
	}
	return 0;
}

bool InjectionBeforeAllocSelf(HANDLE process, PVOID mem, PInternalVars s) {
	ICHookerLowLevelPartSetHooker(ConvertAddrByBase(&InjectionICHook, thismoduleinfo.lpBaseOfDll, mem));
	PVOID ic = (PVOID)PFindData(ByfronICPattern, 8, (ULONG_PTR)s->byfron.lpBaseOfDll, s->byfron.SizeOfImage, process, 100000);
	if (ic == (PVOID)-1) { return 0; }
	s->ICAddr = ic;
	return 1;
}
bool InjectionAllocSelf(HANDLE process, PInternalVars s, MODULEINFO thismodinfo) {

	PVOID selfmem = VirtualAllocEx(process, NULL, thismodinfo.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (InjectionBeforeAllocSelf(process, selfmem, s) == 0) { goto err; }
	if (selfmem == NULL) { return 0; }
	if (VirtualQueryEx(process, selfmem, &s->InjectionHiddenMemory[s->InjectionHiddenMemoryC], sizeof(MEMORY_BASIC_INFORMATION)) == 0) { goto err; };
	s->InjectionHiddenMemoryC++;
	if (WriteProcessMemory(process, selfmem, thismodinfo.lpBaseOfDll, thismodinfo.SizeOfImage, NULL) == 0) { goto err; };
	s->Injector = selfmem;
	return 1;

err:
	if (selfmem != 0)
		VirtualFreeEx(process, selfmem, 0, MEM_RELEASE);
	return 0;


}

typedef void(*InitializeFunc)();
bool InjectionSetupInternalPart(HANDLE process, PInternalVars s) {
	void* addy = ConvertAddrByBase(&InjectionDllCaller, thismoduleinfo.lpBaseOfDll, s->Injector);
	return CreateTPDirectThread(process, addy);
}

bool GetThisModuleInfo() {
	HMODULE thismod = GetModuleHandleA(NULL);
	if (thismod == NULL) { return 0; }
	return GetModuleInformation(GetCurrentProcess(), thismod, &thismoduleinfo, sizeof(MODULEINFO));
}

ULONG_PTR ConvertAddrByBase(ULONG_PTR Addr, ULONG_PTR OldBase, ULONG_PTR NewBase) {
	return Addr - OldBase + NewBase;
}
void* ConvertAddrByBase(const void* Addr, const void* OldBase, const void* NewBase) {
	return (void*)((ULONG_PTR)Addr - (ULONG_PTR)OldBase + (ULONG_PTR)NewBase);
}

InternalVars injection_vars = {};
MODULEINFO thismoduleinfo = {};