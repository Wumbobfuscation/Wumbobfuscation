# Windows OS Internals 
Overview of Windows OS internals for use in tool development.

### Export Directory & Export Address Table (EAT)
Within each DLL header is an Export Directory structure, which contains three pointers to the Export Address Table:

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

The Export Directory is a double-linked list where the function name pointed to in the `AddressOfNames` field points to its Relative Virtual Address (RVA) stored in `AddressOfFunctions` and its ordinal number stored in `AddressOfNameOrdinals`.

Each time a Portable Executable (PE) loader needs to resolve the address of an exported function, it accesses a parsed Export Address Table by referencing the function name stored in `AddressOfNames`, and retrieving the Relative Virtual Address (RVA) that it points to in `AddressOfFunctions`.

If the loader only knows the ordinal number of the function, it can determine the location of the address in `AddressOfNames` by calculating the given ordinal number minus the base ordinal stored in the `Base` field of the Export Directory. The resulting ordinal number can be used to reference the corresponding address in `AddressOfNames`.

### Import Directory, Import Lookup Table (ILT), & Import Address Table (IAT)
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

