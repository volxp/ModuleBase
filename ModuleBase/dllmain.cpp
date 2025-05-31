
#include <thread>
#include <NamedPipe.hpp>


void threadA() {
    Globals::DataModel = Utils::Task->GetDataModel();
    if (!Utils::Task->isGameLoaded(Globals::DataModel)) {        // make sure injected ingame (ingame = 31, home = 15)
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        return threadA();
    }

    Globals::LuaState = Utils::Task->GetLuaState(Globals::DataModel);
    if (!Utils::Task->CreateThread())
        return threadA();

    Execution::cBase->Execute(Globals::exploitThread, "print('Injected')");
    while (true) {

    }
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        std::thread(threadA).detach();
        startpipe();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

