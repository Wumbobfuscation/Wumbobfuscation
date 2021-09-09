# Wumbobfuscation
Wumbo Windows Obfuscation.

Detailed analysis of Portable Executable (PE) parsing techniques used to return pointers to Windows API functions to avoid calling them directly in code.

The C/C++ code exemplifying the obfuscation tehniques below was originally written by [Sektor7 Institute](https://institute.sektor7.net/) within their [Malware Development Intermediate](https://institute.sektor7.net/courses/rto-maldev-intermediate) course. The explanations and analysis of the code are my own.

### Export Directory
Within each DLL header is an Export Directory structure. The Export Directory is a double-linked list where the function name pointed to in the `AddressOfNames` field points to its Relative Virtual Address (RVA) stored in `AddressOfFunctions` and its ordinal number stored in `AddressOfNameOrdinals`:

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

The below function exemplifies a manual reference of the `_IMAGE_EXPORT_DIRECTORY` structure in order to access the Export Address Table (EAT) and store a pointer to a given process. To access the `_IMAGE_EXPORT_DIRECTORY`, a chain of pointers reference multiple Matryoshka-esque data structures, beginning with the `e_lfanew` field in the `IMAGE_DOS_HEADER`, which points to [`IMAGE_NT_HEADERS`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64) which points to [`IMAGE_OPTIONAL_HEADER`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32), which itself contains a pointer to the [`IMAGE_DATA_DIRECTORY`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory), which contains a pointer to the `_IMAGE_EXPORT_DIRECTORY`.

A visual reference for this and other PE structure data is available at [OpenRCE](http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf).

```c++
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName) {

    // store the base address of the module input in the hMod argument
    // Base Address + RVA = Virtual Address
    char * pBaseAddr = (char *) hMod;
    
   // parse the PE/NT headers and retrieve RVA pointers to main headers/structures
   // templates to these structures are located in "C:\Program Files (x86)\Windows Kits\10\Include\10\um\winnit.h" 
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

If the value of `sProcName` is not an ordinal, it will be the function name itself. Using the Export Directory's `NumberOfNames` array to determine the size of the `AddressOfNames` array, the program then loops through the `AddressOfNames` array to match the function name stored in `sProcName` parameter to its equivalent exported function. A pointer to the virtual address of the function is then stored in the `pProcAddr` variable.

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

`// TODO: Check whether the RVA is forwarded to an external library function`

To determine the desired process, the function takes the required DLL `hMod` and the process name `sProcName` as arguments:

```c++
typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "VirtualAlloc");
```

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


