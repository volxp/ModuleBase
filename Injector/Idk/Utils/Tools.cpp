#include "Tools.h"
#include <tlhelp32.h>

SYSTEM_PROCESS_INFORMATION* FindProcessByModuleName(const wchar_t* modname) {
	SYSTEM_PROCESS_INFORMATION* Processes = (SYSTEM_PROCESS_INFORMATION*)malloc(0x400000);
	SYSTEM_PROCESS_INFORMATION* ret = NULL;
	SYSTEM_PROCESS_INFORMATION* ProcessCur;
	goto s;
end:
	return ret;
s:

	if ((DWORD)NtF("NtQuerySystemInformation")(SystemProcessInformation, Processes, 0x400000, NULL) != 0) { goto end; };

	ProcessCur = Processes;
	while (ProcessCur->NextOffset) {
		if (ProcessCur->ImageName.Buffer != 0) {
			if (wcscmp(ProcessCur->ImageName.Buffer, modname) == 0) {
				ret = ProcessCur;
				goto end;
			}
		}
		ProcessCur = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)ProcessCur + ProcessCur->NextOffset);
	}
	goto end;
}

MODULEINFO FindModuleByNameInProcess(HANDLE process, const wchar_t* modname) {
	MODULEINFO info = { 0 };
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));

	if (hSnapshot != INVALID_HANDLE_VALUE) {
		MODULEENTRY32W me;
		me.dwSize = sizeof(me);

		if (Module32FirstW(hSnapshot, &me)) {
			do {
				if (_wcsicmp(me.szModule, modname) == 0) {
					info.lpBaseOfDll = me.modBaseAddr;
					info.SizeOfImage = me.modBaseSize;
					info.EntryPoint = me.hModule;
					break;
				}
			} while (Module32NextW(hSnapshot, &me));
		}
		CloseHandle(hSnapshot);
	}
	return info;
}

ULONG_PTR boffset(SIZE_T size, ULONG_PTR start, ULONG_PTR cur) {
	return (cur - start) % size;
}

ULONG_PTR PFindData(const BYTE* data, ULONG_PTR dsize, ULONG_PTR startpos, SIZE_T fsize, HANDLE hProcess, SIZE_T bufsize) {
	BYTE* buf = (BYTE*)VirtualAlloc(NULL, bufsize, MEM_COMMIT, PAGE_READWRITE);
	BYTE* subbuf = (BYTE*)VirtualAlloc(NULL, dsize, MEM_COMMIT, PAGE_READWRITE);
	ULONG_PTR cur = startpos;
	while (cur - startpos < fsize) {
		if (boffset(bufsize, startpos, cur) == 0) {
			ReadProcessMemory(hProcess, (LPVOID)cur, buf, bufsize, NULL);
		}
		if (buf[boffset(bufsize, startpos, cur)] == data[0]) {
			ReadProcessMemory(hProcess, (LPVOID)cur, subbuf, dsize, NULL);
			ULONG_PTR subcur = 1;
			while (subcur < dsize & cur + subcur - startpos < fsize) {
				if (subbuf[subcur] != data[subcur]) {
					break;
				}
				subcur++;
			}

			if (subcur == dsize) {
				VirtualFree(buf, 0, MEM_RELEASE);
				VirtualFree(subbuf, 0, MEM_RELEASE);
				return  cur;
			}
		}
		cur++;
	}
	VirtualFree(buf, 0, MEM_RELEASE);
	VirtualFree(subbuf, 0, MEM_RELEASE);
	return -1;
}