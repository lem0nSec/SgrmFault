#include "StdAfx.h"
#include "utils.h"


BOOL
EnableCurrentProcessPrivilege(_In_ const wchar_t* SePrivilege)
{
    BOOL status = FALSE;
    HANDLE hToken = 0;
    TOKEN_PRIVILEGES TokenPrivileges{};
    PRIVILEGE_SET PrivilegeSet{};
    LUID luid{};

    if (!LookupPrivilegeValueW(NULL, SePrivilege, &luid)) {
        goto Exit;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        goto Exit;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Luid = luid;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        goto Exit;
    }

    PrivilegeSet.PrivilegeCount = 1;
    PrivilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
    PrivilegeSet.Privilege[0].Luid = luid;
    PrivilegeSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!PrivilegeCheck(hToken, &PrivilegeSet, &status)) {
        goto Exit;
    }

Exit:
    if (hToken) {
        CloseHandle(hToken);
    }

    return status;
}


DWORD
FindProcessId(_In_ const wchar_t* processName)
{
    HANDLE hSnap = 0;
    PROCESSENTRY32W entry{};
    DWORD processId = 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE || !hSnap) {
        goto Exit;
    }

    entry.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32First(hSnap, &entry)) {
        while (Process32Next(hSnap, &entry)) {
            if (!_wcsicmp(processName, entry.szExeFile)) {
                processId = entry.th32ProcessID;
                break;
            }
        }
    }

Exit:
    if (hSnap) {
        CloseHandle(hSnap);
    }

    return processId;
}

BOOL
ResolveModuleSectionBase(
    _In_ const wchar_t* moduleName,
    _In_ const char* sectionName,
    _Out_ PMODULE_SECTION_INFORMATION pSectionInfo)
{
    BOOL status = FALSE;
    HMODULE hCurrent = 0;
    PIMAGE_DOS_HEADER pIDH = nullptr;
    PIMAGE_NT_HEADERS pINH = nullptr;
    PIMAGE_SECTION_HEADER pISH = nullptr;
    unsigned int i = 0;

    if (!moduleName ||
        !sectionName) {
        goto Exit;
    }

    if (!pSectionInfo) {
        goto Exit;
    }
    *pSectionInfo = {};

    hCurrent = LoadLibrary(moduleName);
    if (!hCurrent) {
        goto Exit;
    }

    pIDH = (PIMAGE_DOS_HEADER)hCurrent;
    pINH = (PIMAGE_NT_HEADERS)((DWORD64)hCurrent + (DWORD64)pIDH->e_lfanew);
    pISH = IMAGE_FIRST_SECTION(pINH);

    for (i = 0; i < pINH->FileHeader.NumberOfSections; i++, pISH++) {
        if (!strncmp((char*)pISH->Name, sectionName, IMAGE_SIZEOF_SHORT_NAME)) {
            pSectionInfo->sectionBase = (void*)((PBYTE)hCurrent + pISH->VirtualAddress);
            pSectionInfo->sectionVirtualSize = pISH->Misc.VirtualSize;
            pSectionInfo->moduleBase = (void*)hCurrent;
            status = TRUE;
            break;
        }
    }

Exit:
    return status;
}

BOOL
CreateProcessAsPPL(
    _In_ LPSTR lpCommandLine,
    _In_ LPSTARTUPINFOEXA lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL status = FALSE;
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = nullptr;
    SIZE_T szAttrList = 0;
    DWORD protectionLevel = PROTECTION_LEVEL_WINTCB;

    if (!lpCommandLine || !lpStartupInfo || !lpProcessInformation) {
        goto Exit;
    }

    *lpProcessInformation = {};

    if (lpStartupInfo->StartupInfo.cb != sizeof(STARTUPINFOEXA)) {
        lpStartupInfo->StartupInfo.cb = sizeof(STARTUPINFOEXA);
    }

    InitializeProcThreadAttributeList(nullptr, 1, 0, &szAttrList);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !szAttrList) {
        goto Exit;
    }

    pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)LocalAlloc(LPTR, szAttrList);
    if (!pAttrList) {
        goto Exit;
    }

    lpStartupInfo->lpAttributeList = pAttrList;

    if (!InitializeProcThreadAttributeList(lpStartupInfo->lpAttributeList, 1, 0, &szAttrList)) {
        goto Exit;
    }

    if (!UpdateProcThreadAttribute(
        lpStartupInfo->lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
        &protectionLevel, sizeof(DWORD), nullptr, nullptr)) {
        goto Exit;
    }

    status = CreateProcessA(
        nullptr, lpCommandLine,
        nullptr, nullptr,
        TRUE,
        CREATE_PROTECTED_PROCESS | EXTENDED_STARTUPINFO_PRESENT,
        nullptr, nullptr,
        &lpStartupInfo->StartupInfo, lpProcessInformation);

Exit:
    if (pAttrList) {
        DeleteProcThreadAttributeList(pAttrList);
        LocalFree(pAttrList);
    }

    return status;
}

// credits to @tirannido
// took from --> https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CommonUtils/FileOpLock.cpp
static
void
CreateFileLock(_In_ HANDLE hFile, _In_ LPOVERLAPPED overlapped)
{
    REQUEST_OPLOCK_INPUT_BUFFER inputBuffer{};
    REQUEST_OPLOCK_OUTPUT_BUFFER outputBuffer{};
    DWORD err = 0;

    inputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    inputBuffer.StructureLength = sizeof(inputBuffer);
    inputBuffer.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
    inputBuffer.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;

    outputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    outputBuffer.StructureLength = sizeof(outputBuffer);

    DeviceIoControl(
        hFile,
        FSCTL_REQUEST_OPLOCK,
        &inputBuffer,
        sizeof(inputBuffer),
        &outputBuffer,
        sizeof(outputBuffer),
        NULL,
        overlapped);

    if (GetLastError() != ERROR_IO_PENDING) {
        printf("Oplock Failed %d\n", err);
        ExitProcess(-1);
    }
}

HANDLE SetOplockOnFile(_In_ const wchar_t* fileToLock, _Inout_ LPOVERLAPPED lpOverlapped)
{
    HANDLE hFile{};

    if (!lpOverlapped) {
        return 0;
    }

    *lpOverlapped = {};

    hFile = CreateFile(
        fileToLock,
        GENERIC_READ, 0,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, nullptr);
    if (hFile == INVALID_HANDLE_VALUE || !hFile) {
        return 0;
    }

    lpOverlapped->hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!lpOverlapped->hEvent) {
        CloseHandle(hFile);
        return 0;
    }

    CreateFileLock(hFile, lpOverlapped);

    return hFile;
}
