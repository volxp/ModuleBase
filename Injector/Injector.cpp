#include "main.h"
#include "Injection.h"
#include <tlhelp32.h>
#include <fstream>
#include <algorithm>
#include <map>
#include <filesystem>
#include <shlwapi.h>
#include <dpapi.h>
#include <shlobj.h>
#include <nlohmann/json.hpp>
#include <wininet.h>
#include <Thread>
#include "Update/Offsets.hpp"
#include <set>
#include <tlhelp32.h>
#include <tchar.h>
/*
THIS INJECTOR WAS MADE BY BYTECODE!!! Github:
https://github.com/Deni210/Roblox-MMap-Injector

 This is an optimized version.
 NOTE: THIS INJECTOR IS DETECTED ASFUCK !!! DO NOT EXPLOIT ON YOUR MAIN ACCOUNT!

*/
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "fmt.lib")

using json = nlohmann::json;
const std::string exploitDLLPath = "Module.dll";
namespace fs = std::filesystem;



HANDLE pHandle;
uintptr_t sectionBase;

std::map<std::string, uintptr_t> manualMaps;
std::vector<std::pair<std::string, uintptr_t>> imports;

namespace Mapper {
	uintptr_t Map(std::string path);
}

template <typename T>
T Read(uintptr_t address) {
	T buffer{};
	SIZE_T bytesRead;

	if (ReadProcessMemory(pHandle, (LPCVOID)address, &buffer, sizeof(T), &bytesRead) && bytesRead == sizeof(T)) {
		return buffer;
	}

	return T();
}

template <typename T>
bool Write(uintptr_t address, const T& value) {
	SIZE_T bytesWritten;
	return WriteProcessMemory(pHandle, (LPVOID)address, &value, sizeof(T), &bytesWritten) && bytesWritten == sizeof(T);
}

enum class LogType { Error, Success, Info, Warn };

std::string ResolveAPI(const std::string& path) {

	if (fs::exists("ucrtbase.dll")) {
		std::cout << "S1";
		system("pause");
	}
	if (fs::exists("ntdll.dll")) {
		std::cout << "S1";
		system("pause");
	}
	if (fs::exists("advapi32.dll")) {
		std::cout << "S1";
		system("pause");
	}
	if (fs::exists("kernelbase.dll")) {
		std::cout << "S1";
		system("pause");
	}



	if (path.find("api-ms-win-crt-") == 0) {
		return "ucrtbase.dll";
	}
	else if (path.find("api-ms-win-core-") == 0) {
		if (path.find("rtlsupport") != std::string::npos) {
			return "ntdll.dll";
		}
		if (path.find("localization-obsolete") != std::string::npos || path.find("string-obsolete") != std::string::npos) {
			return "kernelbase.dll";
		}
		return "kernel32.dll";
	}
	else if (path.find("api-ms-win-security-") == 0 || path.find("api-ms-win-eventing-") == 0) {
		return "advapi32.dll";
	}
	return path;
}

bool ExistsImport(std::string path) {
	HMODULE hModules[1024];
	DWORD cbNeeded;

	std::string transformedPath = ResolveAPI(path);
	std::transform(transformedPath.begin(), transformedPath.end(), transformedPath.begin(), ::tolower);

	if (EnumProcessModules(pHandle, hModules, sizeof(hModules), &cbNeeded)) {
		DWORD numModules = cbNeeded / sizeof(HMODULE);
		for (DWORD i = 0; i < numModules; ++i) {
			char szModName[MAX_PATH];
			if (GetModuleFileNameExA(pHandle, hModules[i], szModName, sizeof(szModName))) {
				std::string szPath(szModName);
				std::transform(szPath.begin(), szPath.end(), szPath.begin(), ::tolower);

				if (PathFindFileNameA(szPath.c_str()) == transformedPath) {
					return true;
				}
			}
		}
	}

	return false;
}

uint64_t GetImportSize(const std::string& path) {
	uint64_t total_size = 0;

	HMODULE hModule = LoadLibraryExA(path.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!hModule) {
		return NULL;
	}

	auto* dosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		FreeLibrary(hModule);
		return NULL;
	}

	auto* ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		FreeLibrary(hModule);
		return NULL;
	}

	auto importVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!importVA) {
		FreeLibrary(hModule);
		return std::filesystem::file_size(path);
	}

	auto* importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importVA);

	while (importDesc && importDesc->Name) {
		std::string importName = (char*)((BYTE*)hModule + importDesc->Name);
		std::string transformedImport = ResolveAPI(importName);

		if (ExistsImport(transformedImport)) {
			++importDesc;
			continue;
		}
		// _CRT_SECURE_NO_WARNINGS
		std::filesystem::path importPath = transformedImport;
		if (!std::filesystem::exists(importPath)) {
			importPath = std::filesystem::path(getenv("SystemRoot")) / "System32" / transformedImport;
		}

		if (std::filesystem::exists(importPath)) {
			total_size += std::filesystem::file_size(importPath) + 0x100;
		}

		total_size += GetImportSize(importPath.string());

		++importDesc;
	}

	FreeLibrary(hModule);
	return std::filesystem::file_size(path) + total_size;
}

std::vector<std::pair<std::string, uintptr_t>> GetImports(const std::string& path, uintptr_t allocated_mem) {
	std::vector<std::pair<std::string, uintptr_t>> imports;

	imports.emplace_back(path, allocated_mem);

	uintptr_t currentMem = allocated_mem + std::filesystem::file_size(path) + 0x100; // skip the main dll

	HMODULE hModule = LoadLibraryExA(path.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!hModule) {
		return imports;
	}

	auto* dosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		FreeLibrary(hModule);
		return imports;
	}

	auto* ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		FreeLibrary(hModule);
		return imports;
	}

	auto importVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!importVA) {
		FreeLibrary(hModule);
		return imports;
	}

	auto* importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importVA);

	while (importDesc && importDesc->Name) {
		std::string importName = (char*)((BYTE*)hModule + importDesc->Name);

		std::string transformedImport = ResolveAPI(importName);

		if (ExistsImport(transformedImport)) {
			++importDesc;
			continue;
		}

		uintptr_t importAddress = currentMem;
		imports.emplace_back(transformedImport, importAddress);

		std::filesystem::path importPath = transformedImport;
		if (!std::filesystem::exists(importPath)) {
			importPath = std::filesystem::path(getenv("SystemRoot")) / "System32" / transformedImport;
		}

		if (std::filesystem::exists(importPath)) {
			currentMem += std::filesystem::file_size(importPath) + 0x100;

			auto subImports = GetImports(importPath.string(), currentMem);
			imports.insert(imports.end(), subImports.begin(), subImports.end());
		}
		else {
			spdlog::error((std::ostringstream() << "Unable to find Import: " << importName).str());
		}

		++importDesc;
	}

	FreeLibrary(hModule);
	return imports;
}



uintptr_t GetModuleBaseAddress(DWORD processId, const char* moduleName) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	uintptr_t baseAddress = 0;

	if (Module32First(snapshot, &moduleEntry)) {
		do {
			if (_stricmp(moduleEntry.szModule, moduleName) == 0) {
				baseAddress = (uintptr_t)moduleEntry.modBaseAddr;
				break;
			}
		} while (Module32Next(snapshot, &moduleEntry));
	}

	CloseHandle(snapshot);
	return baseAddress;
}

uintptr_t RVAVA(uintptr_t RVA, PIMAGE_NT_HEADERS NtHeaders, uint8_t* RawData)
{
	PIMAGE_SECTION_HEADER FirstSection = IMAGE_FIRST_SECTION(NtHeaders);

	for (PIMAGE_SECTION_HEADER Section = FirstSection; Section < FirstSection + NtHeaders->FileHeader.NumberOfSections; Section++)
		if (RVA >= Section->VirtualAddress && RVA < Section->VirtualAddress + Section->Misc.VirtualSize)
			return (uintptr_t)RawData + Section->PointerToRawData + (RVA - Section->VirtualAddress);

	return NULL;
}

uintptr_t GetFunctionOffset(uintptr_t base, LPCSTR libname, LPCSTR functionName) {
	HMODULE exported = LoadLibrary(libname);
	if (!exported)
		return NULL;

	return base + ((uintptr_t)GetProcAddress(exported, functionName) - (uintptr_t)exported);
}

bool ResolveImports(uint8_t* RawData, PIMAGE_NT_HEADERS NtHeaders, HANDLE pHandle)
{
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RVAVA(NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, NtHeaders, RawData);

	if (!NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		return true;

	LPSTR ModuleName = NULL;
	while (ModuleName = (LPSTR)RVAVA(ImportDescriptor->Name, NtHeaders, RawData))
	{
		uintptr_t ModuleHandle = Mapper::Map(ModuleName);
		if (!ModuleHandle)
		{
			spdlog::error((std::ostringstream() << "Failed to resolve Import: " << ModuleName).str());
			continue;
		}

		PIMAGE_THUNK_DATA ThunkData = (PIMAGE_THUNK_DATA)RVAVA(ImportDescriptor->FirstThunk, NtHeaders, RawData);

		while (ThunkData->u1.AddressOfData)
		{
			if (ThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				uintptr_t resolved = GetFunctionOffset(ModuleHandle, ModuleName, (LPCSTR)(ThunkData->u1.Ordinal & 0xFFFF));
				ThunkData->u1.Function = resolved;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)RVAVA(ThunkData->u1.AddressOfData, NtHeaders, RawData);
				uintptr_t resolved = GetFunctionOffset(ModuleHandle, ModuleName, (LPCSTR)ImportByName->Name);
				ThunkData->u1.Function = resolved;
			}
			ThunkData++;
		}
		ImportDescriptor++;
	}

	return true;
}

BOOL RelocateImage(uintptr_t p_remote_img, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
	struct reloc_entry
	{
		ULONG to_rva;
		ULONG size;
		struct
		{
			WORD offset : 12;
			WORD type : 4;
		} item[1];
	};

	uintptr_t delta_offset = p_remote_img - nt_head->OptionalHeader.ImageBase;
	if (!delta_offset) return true; else if (!(nt_head->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return false;
	reloc_entry* reloc_ent = (reloc_entry*)RVAVA(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_head, (uint8_t*)p_local_img);
	uintptr_t reloc_end = (uintptr_t)reloc_ent + nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (reloc_ent == nullptr)
		return true;

	while ((uintptr_t)reloc_ent < reloc_end && reloc_ent->size)
	{
		DWORD records_count = (reloc_ent->size - 8) >> 1;
		for (DWORD i = 0; i < records_count; i++)
		{
			WORD fix_type = (reloc_ent->item[i].type);
			WORD shift_delta = (reloc_ent->item[i].offset) % 4096;

			if (fix_type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (fix_type == IMAGE_REL_BASED_HIGHLOW || fix_type == IMAGE_REL_BASED_DIR64)
			{
				uintptr_t fix_va = (uintptr_t)RVAVA(reloc_ent->to_rva, nt_head, (uint8_t*)p_local_img);

				if (!fix_va)
					fix_va = (uintptr_t)p_local_img;

				*(uintptr_t*)(fix_va + shift_delta) += delta_offset;
			}
		}

		reloc_ent = (reloc_entry*)((LPBYTE)reloc_ent + reloc_ent->size);
	}

	return true;
}

uintptr_t FindImportAddress(const std::string& importName) {
	for (const auto& import : imports) {
		if (_stricmp(import.first.c_str(), importName.c_str()) == 0) {
			return import.second;
		}
	}
	return NULL;
}

uintptr_t FindMappedModule(std::string path) {
	HMODULE hModules[1024];
	DWORD cbNeeded;

	std::string transformedTarget = ResolveAPI(path);
	std::transform(transformedTarget.begin(), transformedTarget.end(), transformedTarget.begin(), ::tolower);

	if (EnumProcessModules(pHandle, hModules, sizeof(hModules), &cbNeeded)) {
		DWORD numModules = cbNeeded / sizeof(HMODULE);
		for (DWORD i = 0; i < numModules; ++i) {
			char szModName[MAX_PATH];
			if (GetModuleFileNameExA(pHandle, hModules[i], szModName, sizeof(szModName))) {
				std::string modulePath(szModName);
				std::transform(modulePath.begin(), modulePath.end(), modulePath.begin(), ::tolower);
				std::string moduleFilename = PathFindFileNameA(modulePath.c_str());
				if (moduleFilename == transformedTarget) {
					return (uintptr_t)hModules[i];
				}
			}
		}
	}

	return NULL;


}


bool checkAndKillDuplicateRobloxProcesses() {
	const std::wstring targetProcessName = L"RobloxPlayerBeta.exe";
	const std::wstring robloxWindowTitle = L"Roblox";
	std::vector<DWORD> robloxProcessIds;
	std::set<DWORD> exemptProcessIds;
	bool foundMultiple = false;

	EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
		if (!IsWindowVisible(hwnd)) return TRUE;

		wchar_t windowTitle[256];
		GetWindowTextW(hwnd, windowTitle, 256);
		if (wcscmp(windowTitle, L"Roblox") == 0) {
			DWORD pid = 0;
			GetWindowThreadProcessId(hwnd, &pid);
			if (pid != 0) {
				reinterpret_cast<std::set<DWORD>*>(lParam)->insert(pid);
			}
		}
		return TRUE;
		}, reinterpret_cast<LPARAM>(&exemptProcessIds));

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) return false;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	if (!Process32FirstW(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return false;
	}

	do {
		if (_wcsicmp(pe32.szExeFile, targetProcessName.c_str()) == 0) {
			robloxProcessIds.push_back(pe32.th32ProcessID);
		}
	} while (Process32NextW(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	if (robloxProcessIds.size() > 1) {
		foundMultiple = true;

		for (DWORD pid : robloxProcessIds) {
			if (exemptProcessIds.count(pid) > 0) continue;

			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
			if (hProcess) {
				TerminateProcess(hProcess, 0);
				CloseHandle(hProcess);
			}
		}
	}

	return foundMultiple;
}



void setupdlls() {
	try {
		DWORD processes[1024], bytesReturned;
		if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
			spdlog::error("Failed to enumerate processes");
			return;
		}
		DWORD numProcesses = bytesReturned / sizeof(DWORD);
		std::set<std::string> robloxPaths;
		for (DWORD i = 0; i < numProcesses; i++) {
			if (processes[i] == 0) continue;

			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
			if (hProcess == NULL) continue;

			char processPath[MAX_PATH];
			if (GetModuleFileNameExA(hProcess, NULL, processPath, MAX_PATH)) {
				std::string procPath = processPath;
				std::string procName = procPath.substr(procPath.find_last_of("\\") + 1);

				if (procName == "RobloxPlayerBeta.exe") {
					std::string robloxDir = procPath.substr(0, procPath.find_last_of("\\"));
					robloxPaths.insert(robloxDir);
					spdlog::debug("Found Roblox at: {}", robloxDir);
				}
			}
			CloseHandle(hProcess);
		}
		if (robloxPaths.empty()) {
			char localAppData[MAX_PATH];
			if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData) != S_OK) {
				spdlog::error("Failed to fetch appdata");
				return;
			}
			std::string basePath = std::string(localAppData) + "\\Roblox\\Versions";
			try {
				for (const auto& entry : fs::directory_iterator(basePath)) {
					if (!entry.is_directory()) continue;
					fs::path versionPath = entry.path();
					fs::path exePath = versionPath / "RobloxPlayerBeta.exe";

					if (fs::exists(exePath)) {
						robloxPaths.insert(versionPath.string());
					}
				}
			}
			catch (const std::exception& e) {
				spdlog::warn("Error scanning default path: {}", e.what());
			}
		}
		std::vector<std::string> dlls = {
			"msvcp140_1.dll", "msvcp140_2.dll", "msvcp140.dll",
			"vcruntime140.dll", "vcruntime140_1.dll"
		};

		for (const auto& robloxPath : robloxPaths) {
			fs::path versionPath(robloxPath);
			for (const auto& dllName : dlls) {
				fs::path dllPath = versionPath / dllName;
				if (fs::exists(dllPath)) {
					spdlog::debug("Found DLL: {}", dllPath.string());
					std::error_code ec;
					fs::remove(dllPath, ec);
					if (ec) {
						spdlog::error("Failed to remove {}: {}", dllPath.string(), ec.message());
					}
					else {
						spdlog::debug("Deleted: {}", dllPath.string());
					}
				}
			}

			spdlog::debug("Finished checking in: {}", versionPath.string());
		}
	}
	catch (const std::exception& e) {
		spdlog::error("Exception occurred during DLL cleanup: {}", e.what());
	}
}

void renamewindownigger() {
	std::string randoms = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	while (true) {
		std::string randomString;
		for (int i = 0; i < 10; ++i) {
			randomString += randoms[rand() % randoms.length()];
		}
		SetConsoleTitleA(randomString.c_str());
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

uintptr_t Mapper::Map(std::string path) {

	std::string oldPath = path;

	uintptr_t module = FindMappedModule(path);
	if (module)
		return module;

	auto mappedDLL = manualMaps.find(path);
	if (mappedDLL != manualMaps.end())
		return mappedDLL->second;

	uintptr_t dllBase = FindImportAddress(path);

	std::ifstream tFile(path, std::ios::binary | std::ios::ate);
	if (!tFile.is_open())
	{
		path = "C:\\Windows\\System32\\" + path;
		tFile.open(path, std::ios::binary | std::ios::ate);
		if (!tFile.is_open()) {
			exit(EXIT_FAILURE);
		}
	}
	tFile.close();


	if (!dllBase)
		dllBase = FindImportAddress(path);

	manualMaps[oldPath] = dllBase;

	uintptr_t dllSize = std::filesystem::file_size(path);

	DWORD oldprotect;
	VirtualProtectEx(pHandle, (LPVOID)dllBase, dllSize, PAGE_EXECUTE_READWRITE, &oldprotect);

	std::ifstream File(path, std::ios::binary | std::ios::ate);
	if (!File.is_open())
	{
		std::string system32Path = "C:\\Windows\\System32\\" + path;
		File.open(system32Path, std::ios::binary | std::ios::ate);
		if (!File.is_open()) {
			exit(EXIT_FAILURE);
		}
	}
	std::streampos file_size = File.tellg();
	PBYTE buffer = (PBYTE)malloc(file_size);

	File.seekg(0, std::ios::beg);
	File.read((char*)buffer, file_size);
	File.close();

	if (!buffer)
		return NULL;

	PIMAGE_NT_HEADERS ntHeader = (IMAGE_NT_HEADERS*)(buffer + ((IMAGE_DOS_HEADER*)buffer)->e_lfanew);
	PIMAGE_OPTIONAL_HEADER optionalHeader = &ntHeader->OptionalHeader;
	PIMAGE_FILE_HEADER fileHeader = &ntHeader->FileHeader;

	PBYTE dllAddress = (PBYTE)dllBase;

	if (!dllAddress) {
		exit(EXIT_FAILURE);
	};

	uintptr_t entryPoint = (uintptr_t)dllAddress + (uintptr_t)optionalHeader->AddressOfEntryPoint;

	if (path.find(exploitDLLPath) != std::string::npos) {
		Write<uintptr_t>(sectionBase + 0x20, entryPoint);
		Write<uintptr_t>(sectionBase + 0x28, (uintptr_t)dllAddress);

		// SEH support
		auto excep = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			Write<uintptr_t>(sectionBase + 0x30, excep.VirtualAddress);
			Write<uintptr_t>(sectionBase + 0x38, excep.Size);
		}
	}

	if (!RelocateImage((uintptr_t)dllAddress, buffer, ntHeader))
		spdlog::error("Failed to relocate image");

	if (!ResolveImports(buffer, ntHeader, pHandle))
		spdlog::error("Failed to resolve imports");

	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

	for (UINT i = 0; i < fileHeader->NumberOfSections; ++i, ++sectionHeader)
	{
		if (sectionHeader->SizeOfRawData == 0)
			continue;

		LPVOID targetAddress = (LPVOID)(dllAddress + sectionHeader->VirtualAddress);
		LPVOID sourceData = (LPVOID)(buffer + sectionHeader->PointerToRawData);
		SIZE_T dataSize = sectionHeader->SizeOfRawData;

		BOOL writeResult = WriteProcessMemory(pHandle, targetAddress, sourceData, dataSize, nullptr);

		if (!writeResult)
		{

			free(buffer);
			VirtualFreeEx(pHandle, dllAddress, 0, MEM_RELEASE);

			exit(EXIT_FAILURE);
		}
	}

	return dllBase;
}


void checkwhite() {
	std::thread(renamewindownigger).detach();
	system("cls");
	if (!fs::exists(exploitDLLPath)) {
		spdlog::error("Module not found: {}", exploitDLLPath);
		system("pause");
		exit(EXIT_FAILURE);
	}
	spdlog::info("Setting up DLL's");
	setupdlls();
	spdlog::debug("Checking for whitelisted DLL's");
	bool isrobloxlegit = checkAndKillDuplicateRobloxProcesses();

	if (isrobloxlegit) {
		spdlog::error("Roblox ready");
		checkwhite();
	}
	else {
		spdlog::info("Roblox was ready");

	}
}

int wmain(int argc, wchar_t* argv[]) {
	checkwhite();

	SetupNTDLL();
	if (NTDLL == NULL) {
		exit(EXIT_FAILURE);
	}

	if (GetThisModuleInfo() == 0) {
		exit(EXIT_FAILURE);
	} 

	SYSTEM_PROCESS_INFORMATION* RobloxProcessInformation = FindProcessByModuleName(L"RobloxPlayerBeta.exe");
	if (!RobloxProcessInformation) {
		spdlog::error("Roblox not found");
		system("pause");
		exit(EXIT_FAILURE);
	}
	//SuspendEx("explorer.exe");
	injection_vars.RobloxProcessInfo = RobloxProcessInformation;


	pHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, RobloxProcessInformation->ProcessId);
	if (pHandle == NULL) {
		exit(EXIT_FAILURE);
	}

	if (InjectionFindByfron(pHandle, &injection_vars) == 0) {
		exit(EXIT_FAILURE);
	};

	for (DWORD currentThread = 0; currentThread < RobloxProcessInformation->ThreadCount; ++currentThread) {
		const auto& threadInfo = RobloxProcessInformation->ThreadInfos[currentThread];
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadInfo.Client_Id.UniqueThread);
		if (!hThread) {
			continue;
		}

		ULONG_PTR startAddr = 0;
		DWORD status = static_cast<DWORD>(CallSyscall(0x0025, hThread, ThreadQuerySetWin32StartAddress, &startAddr, sizeof(ULONG_PTR), nullptr));
		if (status == 0) {
			ULONG_PTR dllBase = (ULONG_PTR)injection_vars.byfron.lpBaseOfDll;
			ULONG_PTR dllEnd = dllBase + injection_vars.byfron.SizeOfImage;

			if (startAddr >= dllBase && startAddr < dllEnd) {
				SuspendThread(hThread);
			}
		}

		CloseHandle(hThread);
	}

	if (InjectionAllocSelf(pHandle, &injection_vars, thismoduleinfo) == 0) {
		exit(EXIT_FAILURE);
	};

	sectionBase = GetModuleBaseAddress(RobloxProcessInformation->ProcessId, "winsta.dll") + 0x328;
	uint64_t totalSize = GetImportSize(exploitDLLPath);

	DWORD oldProtect;
	if (!VirtualProtectEx(pHandle, (void*)sectionBase, sizeof(uintptr_t) * 8, PAGE_READWRITE, &oldProtect)) {
		exit(EXIT_FAILURE);
	}

	uintptr_t allocated_mem = (uintptr_t)VirtualAllocEx(pHandle, nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!allocated_mem) {
		exit(EXIT_FAILURE);
	}

	imports = GetImports(exploitDLLPath, allocated_mem);

	Write<uintptr_t>(sectionBase, allocated_mem);
	Write<uint64_t>(sectionBase + 0x8, totalSize);
	Write<int>(sectionBase + 0x10, 0);
	Write<int>(sectionBase + 0x18, 0);
	Write<uintptr_t>(sectionBase + 0x20, 0);
	Write<uintptr_t>(sectionBase + 0x28, 0);
	Write<uintptr_t>(sectionBase + 0x30, 0);
	Write<uintptr_t>(sectionBase + 0x38, 0);

	if (InjectionSetupInternalPart(pHandle, &injection_vars) == 0) {
		exit(EXIT_FAILURE);
	};

	do {
		Sleep(1);
	} while (Read<int>(sectionBase + 0x10) != 1);

	Mapper::Map(exploitDLLPath);


	Write<int>(sectionBase + 0x18, 1);

	Sleep(10);

	spdlog::info("Injected to RobloxPlayerBeta.exe!");

	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	CloseHandle(pHandle);
	//std::cin.get();
	exit(EXIT_SUCCESS);

}


