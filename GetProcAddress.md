# Wumbobfuscating GetProcAddress()
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

However, obfuscating the `GetProcAddress()` function itself is more complex, and requires the manual development of a custom `GetProcAddress()`-like function to parse the Portable Executable (PE) file format, locate the Export Directory, enter the Export Address Table (EAT), and retrieve a pointer to a desired function.

---
## Windows OS Internals: Key Concepts
### Export Directory
Within each DLL header is an Export Directory structure. Within the Export Directory, the function name pointed to in the `AddressOfNames` field points to its Relative Virtual Address (RVA) stored in `AddressOfFunctions` and its ordinal number stored in `AddressOfNameOrdinals`:

```c++
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;                   // DLL Name
    DWORD   Base;                   // Base ordinal numner
    DWORD   NumberOfFunctions;      // Number of entries in EAT
    DWORD   NumberOfNames;          // Number of names in the AddressOfNames and AddressOfNameOrdinals arrays
    DWORD   AddressOfFunctions;     // Export Address Table (EAT)
    DWORD   AddressOfNames;         // Pointers to the names of exported functions
    DWORD   AddressOfNameOrdinals;  // Array of indexes to the EAT
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

Each time a Portable Executable (PE) loader needs to resolve the address of an exported function, it accesses a parsed Export Address Table by referencing the function name stored in `AddressOfNames`, and retrieving the Relative Virtual Address (RVA) that it points to in `AddressOfFunctions`.

### Import Directory
When a PE loader loads a module into memory, it locates an import table that holds a pointer to an array of elements. These elements each contain an `_IMAGE_IMPORT_DESCRIPTOR` structure, shown below.

The `_IMAGE_IMPORT_DESCRIPTOR` points to two arrays, the **Import Lookup Table (ILT)**, and the **Import Address Table (IAT)**. Their use cases will be described shortly.

Both the **Import Lookup Table (ILT)**, and the **Import Address Table (IAT)** point to identical locations in a third array called the **Hint / Name Table**, which contains pairs of hints, followed by the names of the imported functions. The hints in this table correspond to those provided in the **Export Address Table (EAT)**.

During loading, the PE loader locates the `_IMAGE_IMPORT_DESCRIPTOR` record and checks the name of the library. To parse its contents, the loader will leverage **Import Lookup Table (ILT)** to access the **Hint / Name Table**, where it attempts to match the hint to the Relative Virtual Address (RVA) of its corresponding imported function within the **Export Address Table (EAT)**. If this succeeds, the Relative Virtual Address (RVA) is written into the **Import Address Table (IAT)**. Otherwise, the loader will retrieve the Relative Virtual Address (RVA) of the imported function by parsing the **Export Address Table (EAT)**.

```c++
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;         // Pointer to Import Lookup Table (ILT)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                 
    DWORD   ForwarderChain;                
    DWORD   Name;                           // Poimter to the name of an imported DLL
    DWORD   FirstThunk;                     // Pointer to Import Address Table (IAT)
} IMAGE_IMPORT_DESCRIPTOR;
```
---
### Developing GetProcAddress() Wumbobfuscation

The below function exemplifies a manual reference of the `_IMAGE_EXPORT_DIRECTORY` structure in order to access the Export Address Table (EAT) and store a pointer to a given process. To access the `_IMAGE_EXPORT_DIRECTORY`, a chain of pointers reference multiple Matryoshka-esque data structures, beginning with the `e_lfanew` field in the `IMAGE_DOS_HEADER`, which points to [`IMAGE_NT_HEADERS`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64) which points to [`IMAGE_OPTIONAL_HEADER`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32), which itself contains a pointer to the [`IMAGE_DATA_DIRECTORY`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory), which contains a pointer to the `_IMAGE_EXPORT_DIRECTORY`.

The global variables `LoadLibrary_t` and `pLoadLibraryA` are discussed further into this overview.

A visual reference for this and other PE structure data is available at [OpenRCE](http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf).

```c++
// Credit: reenz0h (@sektor7net), RTO Malware Development Intermediate course

#include <stdio.h>

typedef HMODULE (WINAPI * LoadLibrary_t)(LPCSTR lpFileName);
LoadLibrary_t pLoadLibraryA = NULL;

FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName) {

    // store the base address of the module input in the hMod argument
    // Base Address + RVA = Virtual Address
    char * pBaseAddr = (char *) hMod;
    
   // parse the PE/NT headers and retrieve RVA pointers to main headers/structures
   // templates to these structures are located in "C:\Program Files (x86)\Windows Kits\10\Include\<VERSION>\um\winnit.h" 
    IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pBaseAddr;
    IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
        
    // parse the IMAGE_DIRECTORY_ENTRY_EXPORT structure within IMAGE_DATA_DIRECTORY to locate the start of the export directory
    IMAGE_DATA_DIRECTORY * pExportDataDir = (IMAGE_DATA_DIRECTORY *) (&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    
    // calculate the address of the export directory
    IMAGE_EXPORT_DIRECTORY * pExportDirAddr = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddr + pExportDataDir->VirtualAddress);
```

The address of the function call should then be instiantiated for future use.

```c++
     void *pProcAddr = NULL;
```

Once the `_IMAGE_EXPORT_DIRECTORY` has been effectively mapped and stored in a variable, the `AddressOfFunctions` (Export Address Table), `AddressOfNames`, and `AddressOfNameOrdinals` fields can be accessed by referencing the virtual addresses of the Export Directory directly.

```c++
    // Base Address + RVA = Virtual Address

    // AddressOfFunctions (Export Address Table)
    DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);
    // AddressOfNames
    DWORD * pFuncNameTbl = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfNames);
    // AddressOfNameOrdinals
    DWORD * pHintsTbl = (WORD *) (pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);
```

Once the Export Directory has been effectively mapped, the parsing process can begin. This is accomplished by referencing either the orginal number or the name of the function, depending on which is stored within the `sProcName` parameter. To determine whether or not `sProcName` stores an ordinal, the parameter is right shifted (`>>`) by 16 bits (2 bytes). If the result equals zero, the value is an ordinal and can be converted to a WORD and mapped to the `Base` field of the Export Directory and to a corresponding virtual address.

If the value of `sProcName` is not an ordinal, it will most likely be the function name itself. Using the Export Directory's `NumberOfNames` array to determine the size of the `AddressOfNames` array, the program then loops through the `AddressOfNames` array to match the function name stored in `sProcName` parameter to its equivalent exported function. A pointer to the virtual address of the function is then stored in the `pProcAddr` variable.

```c++
// resolve function by ordinal
	if (((DWORD_PTR)sProcName >> 16) == 0) {
		WORD ordinal = (WORD) sProcName & 0xFFFF;   // convert to WORD
		DWORD Base = pExportDirAddr->Base;          // first ordinal number

		// check if ordinal is not out of scope
		if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
			return NULL;

		// get the function virtual address = RVA + BaseAddr
		pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[ordinal - Base]);
	}
    
	// resolve function by name
	else {
		// parse through table of function names
		for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
			char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[i];
	
			if (strcmp(sProcName, sTmpFuncName) == 0)	{
				// found, get the function virtual address = RVA + BaseAddr
				pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[pHintsTbl[i]]);
				break;
			}
		}
	}
```

An additional possibility is that the Relative Virtual Address (RVA) of the function is being forwarded to an external library. If this is the case, the external library and the target function will have to be extracted as strings, the library will be loaded into the process recursively, and the target function will be located within it.

In the code segment below, an initial check determines whether forwarding to an external library is taking place by checking wheether the pointer to the function (`pProcAddr`) is located at or after the starting location of the Export Directory (`pExportDirAddr`), and if it is less than the final address of the Export Directory. If so, a pointer is created to the external library is stored in the variable `sFwdDLL`, and a second pointer is created to the forwarded function itself in the variable `sFwdFunction`.

Retrieving the correct location for the second pointer to the forwarded function (`sFwdFunction`) is tricky, and requires a knowledge of the syntax that externally forwarded functions are stored in. This syntax, `library.function`, can be manipulated by using `strchr` to return the position of the dot (`.`) character. All proceeding characters are the function name. To reach these, a single increment (`++`) is used to shift the trailing null byte in `library\x0function` forward, and produce the function name (`function`).

```c++
	// check if found VA is forwarded to external library.function
	if ((char *) pProcAddr >= (char *) pExportDirAddr && 
		(char *) pProcAddr < (char *) (pExportDirAddr + pExportDataDir->Size)) {
		
		// retrieve a copy of external library string by duplicating the pointer to the function
		char * sFwdDLL = _strdup((char *) pProcAddr);
		if (!sFwdDLL) return NULL;
		
		// retrieve external function name
		char * sFwdFunction = strchr(sFwdDLL, '.');	// begin the definition for the function at the dot ---> library.function
		*sFwdFunction = 0;				// set trailing null byte for external library name ---> library\x0function
		sFwdFunction++;					// shift a pointer to the beginning of function name --> function
```

Having captured the function name in the external library, the program can now resolve the function itself through the standard use of `LoadLibraryA()`, which can be called recursively and stored within the `pLoadLibraryA` global variable defined in the very first code block of the program, above.

```c++
		if (pLoadLibraryA == NULL) {
			pLoadLibraryA = (LoadLibrary_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryA");
			if (pLoadLibraryA == NULL) return NULL;
		}
```

Once the pointer to `LoadLibraryA()` has been stored, it can be called to load a handle (`HMODULE`) the external library (`sFwdFLL`). The original variable containing the external library (`sFwdFLL`) can then be deallocated from memory via `free()`.

The desired process address is stored in the variable `pProcAddr` by recursively calling `hlpGetProcAddress()`, which takes a pointer to the external library (`hFwd`) and external function name (`sFwdFunction`) defined in a previous code block.

```c++
		// load the external library
		HMODULE hFwd = pLoadLibraryA(sFwdDLL);
		
		// release the allocated memory for lib.func string copy
		free(sFwdDLL);
		if (!hFwd) return NULL;

		// get the address of function the original call is forwarded to
		pProcAddr = hlpGetProcAddress(hFwd, sFwdFunction);
	}
```

The custom, obfuscated `GetProcAddress()` function then concludes with a `return` statement that provides the address to the given function (`pProcAddr`).

```c++

	return (FARPROC) pProcAddr;
}
```

---
### Use

To determine the desired process, the function takes the required DLL (`hMod`) and the process name (`sProcName`) as arguments. In the example below, a `typedef` statement creates the `VirtualAlloc_t` type using the standard [`VirtualAlloc`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) syntax defined in the Microsoft Docs.

```c++
typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) hlpGetProcAddress(GetModuleHandle(L"KERNEL32.DLL"), "VirtualAlloc");
```

Note that this technique should ideally be combined with the obfuscation of `GetModuleHandle()` function, diescussed separately in this repository.
