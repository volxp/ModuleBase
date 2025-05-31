#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <Update/offsets.hpp>
#include <Tasks/Utils.hpp>

class LuaScriptServer {
private:
    static constexpr const char* PIPE_NAME = "\\\\.\\pipe\\CLDYexecution";
    static constexpr DWORD BUFFER_SIZE = 65536; // 64KB buffer
    HANDLE hPipe;
    bool running;
    std::thread exploitThread;

public:
    LuaScriptServer() : hPipe(INVALID_HANDLE_VALUE), running(false) {}

    ~LuaScriptServer() {
        Stop();
    }

    bool Start() {
        running = true;

        while (running) {
            hPipe = CreateNamedPipeA(
                PIPE_NAME,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                nullptr
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                return false;
            }
            BOOL connected = ConnectNamedPipe(hPipe, nullptr) ?
                TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

            if (connected) {
                HandleClient();
            }
            else {
            }

            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
        }

        return true;
    }

    void Stop() {
        running = false;
        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
        }
        if (exploitThread.joinable()) {
            exploitThread.join();
        }
    }

private:
    void HandleClient() {
        char buffer[BUFFER_SIZE];
        DWORD bytesRead;
        DWORD bytesWritten;

        while (running) {
            BOOL success = ReadFile(
                hPipe,
                buffer,
                BUFFER_SIZE - 1,
                &bytesRead,
                nullptr
            );

            if (!success || bytesRead == 0) {
                if (GetLastError() == ERROR_BROKEN_PIPE) {
                }
                else {
                }
                break;
            }

            buffer[bytesRead] = '\0';
            std::string luaScript(buffer, bytesRead);

            try {
                Execution::cBase->Execute(Globals::exploitThread, luaScript);
                const char* response = "Script executed successfully";
                WriteFile(
                    hPipe,
                    response,
                    strlen(response),
                    &bytesWritten,
                    nullptr
                );
            }
            catch (const std::exception& e) {
                std::string errorMsg = "Execution error: " + std::string(e.what());
                WriteFile(
                    hPipe,
                    errorMsg.c_str(),
                    errorMsg.length(),
                    &bytesWritten,
                    nullptr
                );
            }

            FlushFileBuffers(hPipe);
        }
    }
};

inline int startpipe() {

    LuaScriptServer server;

    std::thread serverThread([&server]() {
        server.Start();
        });


    if (serverThread.joinable()) {
        serverThread.join();
    }
    return 0;
}