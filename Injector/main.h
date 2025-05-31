#pragma once
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <Psapi.h>
#include "Injection.h"
#include "ICHooker.h"
#include "ntdlldefs.h"
#include "ThreadPool.h"
#include "WorkerFactory.h"
#include "Tools.h"
#include "SyscalCaller.h"
#include <spdlog/spdlog.h>

#include <filesystem>
int wmain(int argc, wchar_t* argv[]);
int WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow)
{
    AllocConsole();
    FILE* pCout;
    freopen_s(&pCout, "CONOUT$", "w", stdout);
    FILE* pCin;
    freopen_s(&pCin, "CONIN$", "r", stdin);
    FILE* pCerr;
    freopen_s(&pCerr, "CONOUT$", "w", stderr);
    int argc;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int result = wmain(argc, wargv);
    LocalFree(wargv);
    std::cin.get();

    return result;
}