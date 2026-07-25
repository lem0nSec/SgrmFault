#pragma once


/// <summary>
/// Allocates a shellcode which clones SgrmBroker.exe's
/// handle to SgrmAgent.sys. Then sends multiple device
/// calls to freeze all threads of a given process (first
/// parameter).
/// </summary>
/// <param name="targetProcessName"></param>
/// <param name="pShellcode"></param>
/// <param name="dwShellcode"></param>
/// <returns>bool</returns>
bool
AllocateSgrmShellcode(
    _In_ const wchar_t* targetProcessName,
    _Inout_ void** pShellcode,
    _Inout_ unsigned long* dwShellcode);


/// <summary>
/// Frees a shellcode allocated with
/// AllocateSgrmShellcode.
/// </summary>
void
FreeSgrmShellcode();
