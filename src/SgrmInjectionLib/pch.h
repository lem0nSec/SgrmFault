// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "framework.h"

static constexpr DWORD SGRM_MAILBOX = 0x9C402484;

// These are some mailbox operation.
// They're essentially sub-IOCTL to
// SGRM_MAILBOX.
// HandleFreezeThread is available 
// in old versions of the driver. 
// Newer version return
// STATUS_NOT_IMPLEMENTED.
typedef enum _SGRM_MAILBOX_OPERATION
{
    HandleMapVirtualAddress = 0x1,
    HandleUnmapVirtualAddress = 0x2,
    HandleGetReferencedProcessObject = 0x3,
    HandleDerefenceProcessObject = 0x4,
    HandleNextReferencedProcess = 0x5,
    HandleNextReferencedThread = 0x6,
    HandleFreezeThread = 0xd,
    HandleCopyMemory = 0xf,
    HandleGetThreadContext = 0x13,
    HandlePurgeAll = 0x16
} SGRM_MAILBOX_OPERATION;


// I/O structs aligned by 1.
// SgrmAgent Header InputBuffer
#pragma pack(push, 1)
typedef struct _SGRMAGENT_INPUT_HEADER
{
    SGRM_MAILBOX_OPERATION Operation;
    USHORT SizeOfInput;
} SGRMAGENT_INPUT_HEADER, * PSGRMAGENT_INPUT_HEADER;

typedef struct _SGRMAGENT_OUTPUT_HEADER
{
    SGRM_MAILBOX_OPERATION Operation;
    USHORT SizeOfOutput;
    NTSTATUS StatusCode;
} SGRMAGENT_OUTPUT_HEADER, * PSGRMAGENT_OUTPUT_HEADER;

typedef struct _SGRM_HANDLE_REF_PROCESS_OBJ
{
    SGRMAGENT_INPUT_HEADER Header;
    ULONG64 ProcessId;
    ULONG unk;
} SGRM_HANDLE_REF_PROCESS_OBJ, * PSGRM_HANDLE_REF_PROCESS_OBJ;

typedef struct _SGRM_HANDLE_REF_PROCESS_OBJ_OUTPUT
{
    SGRMAGENT_OUTPUT_HEADER Header;
    PVOID process;
} SGRM_HANDLE_REF_PROCESS_OBJ_OUTPUT, * PSGRM_HANDLE_REF_PROCESS_OBJ_OUTPUT;

typedef struct _SGRM_HANDLE_DEREF_PROCESS_OBJ
{
    SGRMAGENT_INPUT_HEADER Header;
    PVOID peprocess;
} SGRM_HANDLE_DEREF_PROCESS_OBJ, * PSGRM_HANDLE_DEREF_PROCESS_OBJ;

typedef struct _SGRM_HANDLE_THREAD_INPUT
{
    SGRMAGENT_INPUT_HEADER Header;
    PVOID pethread;
    //ULONG unk;
} SGRM_HANDLE_THREAD_INPUT, * PSGRM_HANDLE_THREAD_INPUT;

typedef struct _SGRM_HANDLE_THREAD_OUTPUT
{
    SGRMAGENT_OUTPUT_HEADER Header;
    PVOID Buffer;
} SGRM_HANDLE_THREAD_OUTPUT, * PSGRM_HANDLE_THREAD_OUTPUT;

typedef struct _SGRM_HANDLE_NEXT_REF_THREAD_INPUT {
    SGRMAGENT_INPUT_HEADER Header;
    PVOID process;
    PVOID thread;
} SGRM_HANDLE_NEXT_REF_THREAD_INPUT, * PSGRM_HANDLE_NEXT_REF_THREAD_INPUT;

typedef struct _SGRM_HANDLE_NEXT_REF_THREAD_OUTPUT {
    SGRMAGENT_OUTPUT_HEADER Header;
    PVOID NextThread;
    PVOID buffer2;
} SGRM_HANDLE_NEXT_REF_THREAD_OUTPUT, * PSGRM_HANDLE_NEXT_REF_THREAD_OUTPUT;
#pragma pack(pop)


typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG                   Attributes;
    ACCESS_MASK             DesiredAccess;
    ULONG                   HandleCount;
    ULONG                   ReferenceCount;
    ULONG                   PagedPoolUsage;
    ULONG                   NonPagedPoolUsage;
    ULONG                   Reserved[3];
    ULONG                   NameInformationLength;
    ULONG                   TypeInformationLength;
    ULONG                   SecurityDescriptorLength;
    LARGE_INTEGER           CreationTime;
} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING          Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _REPLACEABLE_POINTER {
    const wchar_t* Module;
    const char* Name;
    PVOID FakePtr;
    PVOID RealPtr;
} REPLACEABLE_POINTER, * PREPLACEABLE_POINTER;

typedef struct _REPLACEABLE_DWORD {
    const wchar_t* processName;
    DWORD FakeDword;
    DWORD RealDword;
} REPLACEABLE_DWORD, * PREPLACEABLE_DWORD;

typedef BOOL(WINAPI* PDEVICEIOCONTROL)(_In_ HANDLE hDevice, _In_ DWORD dwIoControlCode, _In_opt_ LPVOID lpInBuffer, _In_ DWORD nInBufferSize, _Out_opt_ LPVOID lpOutBuffer, _In_ DWORD nOutBufferSize, _Out_opt_ LPDWORD lpBytesReturned, _Inout_opt_ LPOVERLAPPED lpOverlapped);
typedef NTSTATUS(NTAPI* PNTQUERYSYSTEMINFORMATION)(_In_ int SystemInformationClass, _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI* PNTQUERYOBJECT)(_In_opt_ HANDLE Handle, _In_ int ObjectInfoClass, _Out_opt_ PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength);
typedef HLOCAL(WINAPI* PLOCALALLOC) (__in UINT uFlags, __in SIZE_T uBytes);
typedef HLOCAL(WINAPI* PLOCALFREE) (__deref HLOCAL hMem);
typedef int(NTAPI* PWCSCMP)(const wchar_t* string1, const wchar_t* string2);
typedef HANDLE(WINAPI* POPENPROCESS)(_In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ DWORD dwProcessId);
typedef BOOL(WINAPI* PDUPLICATEHANDLE)(_In_ HANDLE hSourceProcessHandle, _In_ HANDLE hSourceHandle, _In_ HANDLE hTargetProcessHandle, _Out_ LPHANDLE lpTargetHandle, _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ DWORD dwOptions);
typedef VOID(WINAPI* PSLEEP)(_In_ DWORD dwMilliseconds);
typedef BOOL(WINAPI* PCLOSEHANDLE)(_In_ HANDLE hObject);
typedef NTSTATUS(NTAPI* PNTSUSPENDPROCESS)(_In_ HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI* PNTRESUMEPROCESS)(_In_ HANDLE ProcessHandle);
typedef VOID(WINAPI* PEXITPROCESS)(_In_ UINT uExitCode);


#endif //PCH_H
