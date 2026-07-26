#pragma once

#define	Add2Ptr(P, I)   ((PVOID)((PUCHAR)(P) + (I)))
#define Sub2Ptr(P, I)	((PVOID)((PUCHAR)(P) - (I)))

typedef struct _MODULE_SECTION_INFORMATION {
	void* moduleBase;
	void* sectionBase;
	DWORD sectionVirtualSize;
} MODULE_SECTION_INFORMATION, * PMODULE_SECTION_INFORMATION;

BOOL
EnableCurrentProcessPrivilege(
	_In_ const wchar_t* SePrivilege);

HANDLE
SetOplockOnFile(
	_In_ const wchar_t* fileToLock,
	_Inout_ LPOVERLAPPED lpOverlapped);

BOOL
ResolveModuleSectionBase(
	_In_ const wchar_t* moduleName,
	_In_ const char* sectionName,
	_Out_ PMODULE_SECTION_INFORMATION pSectionInfo);

BOOL
CreateProcessAsPPL(
	_In_ LPSTR lpCommandLine,
	_In_ LPSTARTUPINFOEXA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation);
