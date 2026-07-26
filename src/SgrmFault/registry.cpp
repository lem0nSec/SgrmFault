#include "StdAfx.h"
#include "utils.h"

BOOL
RegKeyChangeOwner(_In_ const wchar_t* keyPath)
{
    BOOL result = FALSE;
    LSTATUS status{};
    HANDLE hToken{};
    TOKEN_PRIVILEGES tp{};
    PSID pAdminSID = nullptr;
    LUID luid{};
    HKEY hKey{};
    EXPLICIT_ACCESS ExplAccess{};
    PACL pACL = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        goto Exit;
    }

    if (!EnableCurrentProcessPrivilege(L"SeTakeOwnershipPrivilege")) {
        goto Exit;
    }

    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath, 0, WRITE_OWNER, &hKey);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    if (!AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
        &pAdminSID)) {
        goto Exit;
    }

    RtlSecureZeroMemory(&ExplAccess, sizeof(EXPLICIT_ACCESS));
    ExplAccess.grfAccessPermissions = KEY_ALL_ACCESS;
    ExplAccess.grfAccessMode = SET_ACCESS;
    ExplAccess.grfInheritance = NO_INHERITANCE;
    ExplAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ExplAccess.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ExplAccess.Trustee.ptstrName = (LPTSTR)pAdminSID;

    status = SetEntriesInAcl(1, &ExplAccess, nullptr, &pACL);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    status = SetSecurityInfo(
        hKey,
        SE_REGISTRY_KEY,
        OWNER_SECURITY_INFORMATION,
        pAdminSID,
        nullptr,
        nullptr,
        nullptr);

    if (status != ERROR_SUCCESS) {
        goto Exit;
    }
    else {
        result = TRUE;
    }

Exit:
    if (pACL) {
        LocalFree(pACL);
    }
    if (pAdminSID != nullptr) {
        FreeSid(pAdminSID);
    }
    if (hKey) {
        RegCloseKey(hKey);
    }
    if (hToken) {
        CloseHandle(hToken);
    }

    return result;
}


BOOL
RegKeyChangePermissions(_In_ const wchar_t* keyPath)
{
    BOOL result = FALSE;
    LSTATUS status{};
    PSECURITY_DESCRIPTOR pSd = nullptr;
    ULONG ulSdSize = 0;
    HKEY hKey{};
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID pAdminSID = nullptr;
    EXPLICIT_ACCESS ExplAccess{};
    PACL pACL = nullptr;
    const TCHAR* rights = TEXT("D:")      // Discretionary ACL
        TEXT("(A;OICI;GA;;;BA)");   // Allow full control to administrators

    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath, 0, WRITE_DAC, &hKey);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    if (!AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
        &pAdminSID)) {
        RegCloseKey(hKey);
        return 0;
    }

    RtlSecureZeroMemory(&ExplAccess, sizeof(EXPLICIT_ACCESS));
    ExplAccess.grfAccessPermissions = KEY_ALL_ACCESS;
    ExplAccess.grfAccessMode = SET_ACCESS;
    ExplAccess.grfInheritance = NO_INHERITANCE;
    ExplAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ExplAccess.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ExplAccess.Trustee.ptstrName = (LPTSTR)pAdminSID;

    status = SetEntriesInAcl(1, &ExplAccess, nullptr, &pACL);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    status = SetSecurityInfo(
        hKey,
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION,
        pAdminSID, nullptr, nullptr, nullptr);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(rights, SDDL_REVISION_1, &pSd, &ulSdSize)) {
        goto Exit;
    }

    status = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, pSd);

    if (status != ERROR_SUCCESS) {
        goto Exit;
    }
    else {
        result = TRUE;
    }


Exit:
    if (pACL) {
        LocalFree(pACL);
    }
    if (pAdminSID) {
        FreeSid(pAdminSID);
    }
    if (hKey) {
        RegCloseKey(hKey);
    }

    return result;
}


BOOL
RegKeySetValue(
    _In_ const wchar_t* keyPath,
    _In_opt_ const wchar_t* valueName,
    _In_ DWORD dwType,
    _In_ const wchar_t* data,
    _In_ DWORD dwDataSize)
{
    BOOL result = FALSE;
    LSTATUS status{};
    HKEY hKey{};

    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE, &hKey);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    status = RegSetKeyValueW(hKey, nullptr, valueName, dwType, data, dwDataSize);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }
    else {
        result = TRUE;
    }

Exit:
    if (hKey) {
        RegCloseKey(hKey);
    }

    return result;
}

BOOL
DisableProcessCFG(_In_ const wchar_t* targetProcess)
{
    static constexpr ULONGLONG mitigationOptions = 0x20000000000;
    static const wchar_t* ifeoPath =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

    std::wstring keyPath = ifeoPath;
    keyPath += L"\\";
    keyPath += targetProcess;

    HKEY hKey{};
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (status == ERROR_FILE_NOT_FOUND) {
        status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            keyPath.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            nullptr,
            &hKey,
            nullptr);
    }
    if (status != ERROR_SUCCESS) {
        return FALSE;
    }
    RegCloseKey(hKey);

    return RegKeySetValue(
        keyPath.c_str(),
        L"MitigationOptions",
        REG_QWORD,
        reinterpret_cast<const wchar_t*>(&mitigationOptions),
        sizeof(mitigationOptions));
}
