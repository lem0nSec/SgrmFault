#pragma once

#include <Windows.h>
#include <Aclapi.h>
#include <comdef.h>
#include <Dbgeng.h>
#include <hstring.h>
#include <shlwapi.h>
#include <sddl.h>
#include <TlHelp32.h>
#include <AccCtrl.h>
#include <Objbase.h>
#include <conio.h>
#include <dbghelp.h>
#include <SgrmInjectionLib/SgrmInjectionLib.h> // SGRM Shellcode library

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#pragma comment(lib, "dbgeng")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "rpcrt4.lib")  // UuidCreate - Minimum supported OS Win 2000
