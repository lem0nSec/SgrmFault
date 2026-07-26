#pragma once


BOOL
RegKeyChangeOwner(_In_ const wchar_t* keyPath);


BOOL
RegKeyChangePermissions(_In_ const wchar_t* keyPath);


BOOL
RegKeySetValue(
    _In_ const wchar_t* keyPath,
    _In_opt_ const wchar_t* valueName,
    _In_ DWORD dwType,
    _In_ const wchar_t* data,
    _In_ DWORD dwDataSize);

BOOL
DisableProcessCFG(_In_ const wchar_t* targetProcess);
