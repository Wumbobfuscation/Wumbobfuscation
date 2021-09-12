# Wumbobfuscating GetModuleHandle()
The C/C++ code exemplifying the obfuscation techniques below was originally written by [Sektor7 Institute](https://institute.sektor7.net/) within their [Malware Development Essentials](https://institute.sektor7.net/courses/red-team-operator-malware-development-essentials) and [Malware Development Intermediate](https://institute.sektor7.net/courses/rto-maldev-intermediate) courses. The explanations and analysis of the code are entirely my own.

## Background
Standard Windows API function calls can be obfuscated by calling `GetProcAddress()` and `GetModuleHandle()` to store a pointer to a function within a separate variable. The `GetModuleHandle()` function should not take a string of a function name directly, as this would defeat the purpose of obfuscation, so the string must be encrypted separately. This process is exemplified below, using the `VirtualProtect()` function and the XOR key `ABCDEFGHIJKLMNOPQRSTUVWXYZ`, which is a string already present in a compiled Windows Portable Executable (PE) file and therefore significantly less likely to detect.

```c++
// Credit: reenz0h (@sektor7net), RTO Malware Development Essentials course

// XOR Decryption Function
void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}
```
```c++
// XOR Key
char key[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// XOR-encrypted "VirtualProtect"
char sVirtualProtect[] = { 0x17, 0x2b, 0x31, 0x30, 0x27, 0x2b, 0x18, 0x3b, 0x25, 0x3f, 0x29, 0x2e, 0x3a };

XOR((char *) sVirtualProtect, strlen(sVirtualProtect), key, sizeof(key));

// Obfuscated VirtualProtect function call
pVirtualProtect = GetProcAddress(GetModuleHandle("kernel32.dll"), sVirtualProtect)
```

However, obfuscating the `GetModuleHandle()` function itself is more complex, and requires the manual development of a custom `GetModuleHandle()`-like function to parse the Portable Executable (PE) file format, locate the Export Directory, enter the Export Address Table (EAT), and retrieve a pointer to a desired function.

---

## Windows OS Internals: Key Concepts
### Process Environment Block (PEB)
The Process Environment Block (PEB) is a Windows API structure that contains process information. Each Windows process contains one Process Environment Block (PEB). The default syntax of the Process Environment Block (PEB) is subject to change between Windows versions and service packs, however an example is provided in the [Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb), as well as in the `winternl.h` file located at `C:\Program Files (x86)\Windows Kits\10\Include\<VERSION>\um` directory.

```c++
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;      // Pointer to PEB_LDR_DATA
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, *PPEB;
```

When creating the custom `GetModuleHandle()` function, the Process Environment Block (PEB) is the central structure which must be accessed to return the base address of a module (i.e. a Dynamic Link Library (DLL)). For this purpose, the key element in the Process Environment Block (PEB) is `Ldr`, which will contain a pointer to the critical `PEB_LDR_DATA` structure.

#### PEB_LDR_DATA
The [`PEB_LDR_DATA`](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data) structure contains information about the loaded modules for a given process. The `PEB_LDR_DATA` structure is a double-linked-list, which uses the fields `Flink` (forward link) and `Blink` (backward link) to simultaneously point forward, to the next element, and backwards, to the previous element. Note that `Flink` and `Blink` are not shown in the structure syntax below, but are observable in a Windbg instance. 

```c++
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```
The key element in `_PEB_LDR_DATA` is `InMemoryOrderModuleList`, which contains the loaded modules for the given process. Each module in the list contains a pointer to a separate `_LDR_DATA_TABLE_ENTRY` structure, which holds its information. 

#### _LDR_DATA_TABLE_ENTRY
The [`_LDR_DATA_TABLE_ENTRY`](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data) is the structure pointed to by the `PEB_LDR_DATA` fields `Flink` (forward link) and `Blink` (backward link), and which holds the information of its given module. Each module loaded into a process is represented by a `_LDR_DATA_TABLE_ENTRY` structure.

```c++
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

The `DllBase` element contains the base address for the respective module, while `FullDllName` contains its name.

### Thread Environment Block
The [Thread Environment Block](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb) desribes the state of a thread, and can be used to retrieve a pointer to the Process Environment Block (PEB) structure itself (`PEB`). This pointer is containined in the element `ProcessEnvironmentBlock`. In x64 architecture, this field is at offset `0x60`. In x86 architecture, this field is at offset `0x30`.

```c++
typedef struct _TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;
```

---

### Developing GetModuleHandle() Wumbobfuscation
The below function exemplifies a manual reference of the `_PEB` &rarr; `PEB_LDR_DATA` &rarr; `_LDR_DATA_TABLE_ENTRY` structures, the parsing and location of a desired module (i.e. a Dynamic Link Library (DLL), stored in the `sModuleName` parameter, and return of its base address (`pEntry` &rarr; `DllBase`).

Note that, in order for this function to be successful, these structures must be stored in a separate header file (`PEstructs.h`).

```c++
#pragma once

#include <windows.h>

struct PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
};

struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
	//...
};

struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWCH Buffer;
};
	
struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	//...
};
```

In order to locate and access the Process Environment Block (PEB), an `if` statement first determines whether the host architecture is x86 or x64 bit, and then calls a `_readfsdword` or `_readgsdword` function to read the offset of Process Environment Block (PEB) (`ProcEnvBlock`) based on the corresponding architecture.

```c++
// Credit: reenz0h (@sektor7net), RTO Malware Development Intermediate course

#include "PEstructs.h"
#include <stdio.h>

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {

	// retrieve the offset of Process Environment Block (PEB)
#ifdef _M_IX86 
	PEB * ProcEnvBlk = (PEB *) __readfsdword(0x30);
#else
	PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);
#endif

```

Then, using `ProcEnvBlk->ImageBaseAddress` to access the `ImageBaseAddress` element, the base address of the Process Environment Block (PEB) is stored.

```c++

	// return the base address of the target module
	if (sModuleName == NULL) 
		return (HMODULE) (ProcEnvBlk->ImageBaseAddress);
```

Following this, `ProcEnvBlk->Ldr` is used to stored the address of the `PEB_LDR_DATA` structure kept within the `Ldr` element of the Process Environment Block (PEB).

```c++
	PEB_LDR_DATA * Ldr = ProcEnvBlk->Ldr;
```

A null `ModuleList` is created and then populated using `&Ldr->InMemoryOrderModuleList` to reference the `InMemoryOrderModuleList` element of `PEB_LDR_DATA`. Because the `Flink` (forward link) in `InMemoryOrderModuleList` is used to point to each module entry, the first `Flink` will point to the first module entry. For this reason, the pointer `pStartListEntry` is created to hold the address of `ModuleList->Flink`, the first loaded module.

```c++
	LIST_ENTRY * ModuleList = NULL;
	
	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY *  pStartListEntry = ModuleList->Flink;
```

After the address of the first loaded module has been identified and stored as a variable, the entire module list (`InMemoryOrderModuleList`) can be parsed via a `for` loop. This loop should begin at the first loaded module (`pStartListEntry`), and use a separate variable to determine each entry in the list (`pListEntry`). The `for` loop should be set to stop when this separate variable (`pListEntry`) is determined to no longer be pointing to the an entry in the module list (`ModuleList`),  and can use `pListEntry->Flink` to traverse each `Flink` (forward link) to the following module entry.

Within this `for` loop, each instance should store a pointer to the entry (`pEntry`), then check if the module name stored in the element`BaseDllName` is equal to the target module name provided in the parameter `sModuleName`. If the module is found, it is returned by the program. Otherwise, the program returns null.

```c++
	// parse from beginning of InMemoryOrderModuleList
	for (LIST_ENTRY *  pListEntry  = pStartListEntry;  		
					   pListEntry != ModuleList;	    	// walk all list entries
					   pListEntry  = pListEntry->Flink)	{
		
		// retrieve current Data Table Entry
		LDR_DATA_TABLE_ENTRY * pEntry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) pListEntry - sizeof(LIST_ENTRY));

		// check if module is found and return its base address
		if (lstrcmpiW(pEntry->BaseDllName.Buffer, sModuleName) == 0)
			return (HMODULE) pEntry->DllBase;
	}

	// else:
	return NULL;

}
```

## Use
To determine the desired modules, the function takes the module name (`sModuleName`) as an argument. In the example below, a typedef statement creates the VirtualAlloc_t type using the standard [`VirtualAlloc`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) syntax defined in the Microsoft Docs. Because `VirtualAlloc()` is located in the `kernel32.dll` module, the obfuscated `GetModuleHandle()` function (`hlpGetModuleHandle`) takes `(L"KERNEL32.DLL")` as an argument. In doing this, it will parse the aforementioned Process Environment Block (PEB) structures (`_PEB`, `PEB_LDR_DATA`, `_LDR_DATA_TABLE_ENTRY`) to determine the location of `"KERNEL32.DLL"`, for subsequent use in the `GetProcAddress()`.

```c++
typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) GetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "VirtualAlloc");
```

Note that this technique should ideally be combined with the obfuscation of`GetProcAddress()`, discussed separately in this repository.
